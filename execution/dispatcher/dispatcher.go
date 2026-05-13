package dispatcher

import (
	"fmt"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/principal"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/validator"
)

type handler struct {
	Func       execution.HandlerFunc
	Capability validator.Capability
}

// Dispatcher executes UCAN invocations by dispatching them to registered
// handlers.
type Dispatcher struct {
	authority         principal.Signer
	handlers          map[ucan.Command]handler
	validationOpts    []validator.Option
	receiptTimestamps bool
}

// New creates an invocation executor that executes UCAN invocations by
// dispatching them to registered handlers.
//
// The authority is the identity of the local authority, used to verify
// signatures of delegations signed by it and sign receipts for executed tasks.
func New(authority principal.Signer, options ...Option) *Dispatcher {
	cfg := execConfig{}
	for _, opt := range options {
		opt(&cfg)
	}
	return &Dispatcher{
		authority:         authority,
		handlers:          map[ucan.Command]handler{},
		validationOpts:    cfg.validationOpts,
		receiptTimestamps: cfg.receiptTimestamps,
	}
}

func (d *Dispatcher) Handle(capability validator.Capability, fn execution.HandlerFunc) {
	d.handlers[capability.Command()] = handler{Func: fn, Capability: capability}
}

func (d *Dispatcher) Execute(req execution.Request) (execution.Response, error) {
	aud := req.Invocation().Audience()
	if !aud.Defined() {
		aud = req.Invocation().Subject()
	}
	if aud != d.authority.DID() {
		return execution.NewResponse(
			req.Invocation().Task().Link(),
			execution.WithSigner(d.authority),
			execution.WithReceiptTimestamp(d.receiptTimestamps),
			execution.WithFailure(execution.NewInvalidAudienceError(d.authority.DID(), aud)),
		)
	}

	cmd := req.Invocation().Command()
	handler, ok := d.handlers[cmd]
	if !ok {
		return execution.NewResponse(
			req.Invocation().Task().Link(),
			execution.WithSigner(d.authority),
			execution.WithReceiptTimestamp(d.receiptTimestamps),
			execution.WithFailure(NewHandlerNotFoundError(cmd)),
		)
	}

	opts := []validator.Option{validator.WithMetadata(req.Metadata())}
	opts = append(opts, d.validationOpts...)
	if req.Metadata() != nil {
		opts = append(opts, validator.WithProofs(req.Metadata().Delegations()...))
	}

	_, err := validator.Access(
		req.Context(),
		d.authority.Verifier(),
		handler.Capability,
		req.Invocation(),
		opts...,
	)
	if err != nil {
		return execution.NewResponse(
			req.Invocation().Task().Link(),
			execution.WithSigner(d.authority),
			execution.WithReceiptTimestamp(d.receiptTimestamps),
			execution.WithFailure(err),
		)
	}

	res, err := execution.NewResponse(
		req.Invocation().Task().Link(),
		execution.WithSigner(d.authority),
		execution.WithReceiptTimestamp(d.receiptTimestamps),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create response: %w", err)
	}

	err = handler.Func(req, res)
	if err != nil {
		return execution.NewResponse(
			req.Invocation().Task().Link(),
			execution.WithSigner(d.authority),
			execution.WithReceiptTimestamp(d.receiptTimestamps),
			execution.WithFailure(execution.NewHandlerExecutionError(cmd, err)),
		)
	}
	return res, nil
}
