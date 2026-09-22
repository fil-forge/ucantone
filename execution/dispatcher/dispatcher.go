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

// Execute validates the invocation and runs the handler registered for its
// command. A panic anywhere along the way, in a handler or in validation code
// such as a DID resolver or verifier factory, fails that task with a receipt
// instead of escaping to the caller, so one misbehaving invocation cannot take
// down a server that executes many at once.
func (d *Dispatcher) Execute(req execution.Request) (res execution.Response, err error) {
	// recover() alone cannot tell a normal return from panic(nil), which is
	// recovered as nil under GODEBUG=panicnil=1, so the flag is what says
	// whether execute returned.
	returned := false
	defer func() {
		if returned {
			return
		}
		d.panicLogger(req, recover())
		res, err = d.transientFailure(req, execution.NewExecutionPanicError(req.Invocation().Command()))
	}()
	res, err = d.execute(req)
	returned = true
	return res, err
}

// execute is [Dispatcher.Execute] without the recovery boundary.
func (d *Dispatcher) execute(req execution.Request) (execution.Response, error) {
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
		return d.transientFailure(req, execution.NewHandlerExecutionError(cmd, err))
	}
	return res, nil
}

// transientFailure builds the response for a failure that is unexpected and
// likely transient: an error returned from a handler or a recovered panic. The
// receipt asserting it is short-lived, so clients retry rather than cache it.
// Permanent errors are set as error results on the response by the handler.
func (d *Dispatcher) transientFailure(req execution.Request, failure error) (execution.Response, error) {
	respOpts := []execution.ResponseOption{
		execution.WithIssuer(d.authority),
		execution.WithReceiptTimestamp(d.receiptTimestamps),
	}
	if d.handlerErrorReceiptTTL > 0 {
		exp := ucan.Now() + ucan.UnixTimestamp(d.handlerErrorReceiptTTL.Seconds())
		respOpts = append(respOpts, execution.WithReceiptExpiration(exp))
	}
	respOpts = append(respOpts, execution.WithFailure(failure))
	return execution.NewResponse(req.Invocation().Task().Link(), respOpts...)
}

// runHandler calls the handler and turns a panic into a returned error, so a
// misbehaving handler fails its own task the way a returned error does. The
// panic value goes to the configured [PanicLogger]. The receipt tells the
// client that the handler panicked and nothing more. Panics from anywhere else
// in execution are caught by the boundary in [Dispatcher.Execute].
func (d *Dispatcher) runHandler(req execution.Request, res execution.Response, handler execution.HandlerFunc) (err error) {
	// See Execute for why a flag is needed alongside recover().
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
	log.Printf("panic executing %s task %s: %v\n%s",
		req.Invocation().Command(), req.Invocation().Task().Link(), value, buf)
}

// panicStackSize matches the buffer net/http uses for the same purpose.
const panicStackSize = 64 << 10
