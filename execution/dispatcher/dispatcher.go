package dispatcher

import (
	"errors"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/validator"
)

// Dispatcher executes UCAN invocations by dispatching them to registered
// handlers.
type Dispatcher struct {
	authority              ucan.Issuer
	handlers               map[ucan.Command]execution.HandlerFunc
	validationOpts         []validator.Option
	receiptTimestamps      bool
	handlerErrorReceiptTTL time.Duration
	panicLogger            PanicLogger
}

// New creates an invocation executor that executes UCAN invocations by
// dispatching them to registered handlers.
//
// The authority is the identity of the local authority, used to verify
// signatures of delegations signed by it and sign receipts for executed tasks.
func New(authority ucan.Issuer, options ...Option) *Dispatcher {
	cfg := execConfig{
		handlerErrorReceiptTTL: DefaultHandlerErrorReceiptTTL,
		panicLogger:            logPanic,
	}
	for _, opt := range options {
		opt(&cfg)
	}
	return &Dispatcher{
		authority:              authority,
		handlers:               map[ucan.Command]execution.HandlerFunc{},
		validationOpts:         cfg.validationOpts,
		receiptTimestamps:      cfg.receiptTimestamps,
		handlerErrorReceiptTTL: cfg.handlerErrorReceiptTTL,
		panicLogger:            cfg.panicLogger,
	}
}

func (d *Dispatcher) Handle(command ucan.Command, fn execution.HandlerFunc) {
	d.handlers[command] = fn
}

func (d *Dispatcher) Execute(req execution.Request) (execution.Response, error) {
	aud := req.Invocation().Audience()
	if !aud.Defined() {
		aud = req.Invocation().Subject()
	}
	if aud != d.authority.DID() {
		return execution.NewResponse(
			req.Invocation().Task().Link(),
			execution.WithIssuer(d.authority),
			execution.WithReceiptTimestamp(d.receiptTimestamps),
			execution.WithFailure(execution.NewInvalidAudienceError(d.authority.DID(), aud)),
		)
	}

	cmd := req.Invocation().Command()
	handler, ok := d.handlers[cmd]
	if !ok {
		return execution.NewResponse(
			req.Invocation().Task().Link(),
			execution.WithIssuer(d.authority),
			execution.WithReceiptTimestamp(d.receiptTimestamps),
			execution.WithFailure(NewHandlerNotFoundError(cmd)),
		)
	}

	opts := []validator.Option{validator.WithMetadata(req.Metadata())}
	opts = append(opts, d.validationOpts...)
	if req.Metadata() != nil {
		opts = append(opts, validator.WithProofResolver(validator.ProofsFromContainer(req.Metadata())))
	}

	err := validator.ValidateInvocation(
		req.Context(),
		req.Invocation(),
		opts...,
	)
	if err != nil {
		return execution.NewResponse(
			req.Invocation().Task().Link(),
			execution.WithIssuer(d.authority),
			execution.WithReceiptTimestamp(d.receiptTimestamps),
			execution.WithFailure(err),
		)
	}

	res, err := execution.NewResponse(
		req.Invocation().Task().Link(),
		execution.WithIssuer(d.authority),
		execution.WithReceiptTimestamp(d.receiptTimestamps),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create response: %w", err)
	}

	err = d.runHandler(req, res, handler)
	if err != nil {
		respOpts := []execution.ResponseOption{
			execution.WithIssuer(d.authority),
			execution.WithReceiptTimestamp(d.receiptTimestamps),
		}
		// Errors returned from handlers and panics recovered from them are
		// unexpected and likely transient, so the receipt asserting the
		// failure is short-lived. Permanent errors are set as error results
		// on the response by the handler.
		if d.handlerErrorReceiptTTL > 0 {
			exp := ucan.Now() + ucan.UnixTimestamp(d.handlerErrorReceiptTTL.Seconds())
			respOpts = append(respOpts, execution.WithReceiptExpiration(exp))
		}
		respOpts = append(respOpts, execution.WithFailure(execution.NewHandlerExecutionError(cmd, err)))
		return execution.NewResponse(req.Invocation().Task().Link(), respOpts...)
	}
	return res, nil
}

// runHandler calls the handler and turns a panic into a returned error, so a
// misbehaving handler fails its own task instead of taking down the process.
// The panic value goes to the configured [PanicLogger]. The receipt tells the
// client that the handler panicked and nothing more.
func (d *Dispatcher) runHandler(req execution.Request, res execution.Response, handler execution.HandlerFunc) (err error) {
	// recover() alone cannot tell a normal return from panic(nil), which is
	// recovered as nil under GODEBUG=panicnil=1, so the flag is what says
	// whether the handler returned.
	returned := false
	defer func() {
		if returned {
			return
		}
		value := recover()
		d.panicLogger(req, value)
		err = errHandlerPanicked
	}()
	err = handler(req, res)
	returned = true
	return err
}

var errHandlerPanicked = errors.New("handler panicked")

// logPanic is the default [PanicLogger]. It prints the panic and the stack
// through the standard log package, the way net/http reports the panics it
// recovers, so it adds no dependency to a binary that serves HTTP.
func logPanic(req execution.Request, value any) {
	buf := make([]byte, panicStackSize)
	buf = buf[:runtime.Stack(buf, false)]
	log.Printf("ucantone: panic executing %s task %s: %v\n%s",
		req.Invocation().Command(), req.Invocation().Task().Link(), value, buf)
}

// panicStackSize matches the buffer net/http uses for the same purpose.
const panicStackSize = 64 << 10
