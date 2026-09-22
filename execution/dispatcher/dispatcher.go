package dispatcher

import (
	"fmt"
	"log/slog"
	"runtime/debug"
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
	logger                 *slog.Logger
}

// New creates an invocation executor that executes UCAN invocations by
// dispatching them to registered handlers.
//
// The authority is the identity of the local authority, used to verify
// signatures of delegations signed by it and sign receipts for executed tasks.
func New(authority ucan.Issuer, options ...Option) *Dispatcher {
	cfg := execConfig{
		handlerErrorReceiptTTL: DefaultHandlerErrorReceiptTTL,
		logger:                 slog.Default(),
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
		logger:                 cfg.logger,
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
// The panic and its stack are logged; only the panic value reaches the client.
func (d *Dispatcher) runHandler(req execution.Request, res execution.Response, handler execution.HandlerFunc) (err error) {
	defer func() {
		value := recover()
		if value == nil {
			return
		}
		d.logger.LogAttrs(req.Context(), slog.LevelError, "handler panicked",
			slog.String("command", req.Invocation().Command().String()),
			slog.String("task", req.Invocation().Task().Link().String()),
			slog.Any("panic", value),
			slog.String("stack", string(debug.Stack())),
		)
		err = fmt.Errorf("handler panicked: %v", value)
	}()
	return handler(req, res)
}
