package binding

import (
	"context"
	"fmt"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
)

type requestConfig struct {
	invocations []ucan.Invocation
	delegations []ucan.Delegation
	receipts    []ucan.Receipt
}

// RequestOption configures the proofs and supporting UCANs carried alongside
// the invocation in a [Request] built by [NewRequest].
type RequestOption = func(cfg *requestConfig)

// WithDelegations adds delegations to the execution request. They should be
// linked from the invocation to be executed.
func WithDelegations(delegations ...ucan.Delegation) RequestOption {
	return func(cfg *requestConfig) {
		cfg.delegations = append(cfg.delegations, delegations...)
	}
}

// WithReceipts adds receipts to the execution request.
func WithReceipts(receipts ...ucan.Receipt) RequestOption {
	return func(cfg *requestConfig) {
		cfg.receipts = append(cfg.receipts, receipts...)
	}
}

// WithInvocations adds additional invocations to the execution request.
func WithInvocations(invocations ...ucan.Invocation) RequestOption {
	return func(cfg *requestConfig) {
		cfg.invocations = append(cfg.invocations, invocations...)
	}
}

// Request is an [execution.Request] whose invocation arguments have been
// decoded into the typed Args. A handler reads them through Task; see
// [HandlerFunc].
type Request[Args cbg.CBORUnmarshaler] struct {
	execution.Request
	task *Task[Args]
}

// NewRequest decodes inv's arguments into Args and wraps it as a typed
// [Request], attaching any proofs, delegations, or receipts supplied via
// options. It fails if the arguments do not conform to Args.
func NewRequest[Args cbg.CBORUnmarshaler](ctx context.Context, inv ucan.Invocation, options ...RequestOption) (*Request[Args], error) {
	cfg := requestConfig{}
	for _, opt := range options {
		opt(&cfg)
	}
	task, err := NewTask[Args](inv.Subject(), inv.Command(), inv.ArgumentsBytes(), inv.Nonce())
	if err != nil {
		return nil, err
	}
	return &Request[Args]{
		Request: execution.NewRequest(
			ctx,
			inv,
			execution.WithInvocations(cfg.invocations...),
			execution.WithDelegations(cfg.delegations...),
			execution.WithReceipts(cfg.receipts...),
		),
		task: task,
	}, nil
}

// Task returns an object containing just the fields that comprise the task
// for the invocation.
//
// https://github.com/ucan-wg/invocation/blob/main/README.md#task
func (r *Request[Args]) Task() *Task[Args] {
	return r.task
}

// IssuerSetter is implemented by responses that can issue their own receipt and
// therefore need an issuer. [WithIssuer] uses it to set that issuer.
type IssuerSetter interface {
	SetIssuer(ucan.Issuer) error
}

// ResponseOption configures a [Response] as it is built by [NewResponse],
// typically setting its outcome (success or failure), issuer, or metadata.
type ResponseOption[OK cbg.CBORMarshaler] func(r *Response[OK]) error

// WithIssuer sets the issuer used to issue the response's receipt. It fails if
// the underlying response cannot accept one (does not implement [IssuerSetter]).
func WithIssuer[OK cbg.CBORMarshaler](issuer ucan.Issuer) ResponseOption[OK] {
	return func(resp *Response[OK]) error {
		setter, ok := resp.res.(IssuerSetter)
		if !ok {
			return fmt.Errorf("cannot set issuer: underlying response is not an issuer setter")
		}
		return setter.SetIssuer(issuer)
	}
}

// WithReceipt sets a pre-built receipt as the response's outcome instead of
// issuing one from a success or failure value.
func WithReceipt[OK cbg.CBORMarshaler](receipt ucan.Receipt) ResponseOption[OK] {
	return func(resp *Response[OK]) error {
		resp.SetReceipt(receipt)
		return nil
	}
}

// WithSuccess issues and sets a receipt for a successful execution of a task.
func WithSuccess[OK cbg.CBORMarshaler](o OK) ResponseOption[OK] {
	return func(resp *Response[OK]) error {
		return resp.SetSuccess(o)
	}
}

// WithFailure issues and sets a receipt for a failed execution of a task.
func WithFailure[OK cbg.CBORMarshaler](signer ucan.Signer, task cid.Cid, x error) ResponseOption[OK] {
	return func(resp *Response[OK]) error {
		return resp.SetFailure(x)
	}
}

// WithMetadata attaches a metadata container to the response, carried
// alongside the receipt (e.g. transport-specific headers).
func WithMetadata[OK cbg.CBORMarshaler](meta ucan.Container) ResponseOption[OK] {
	return func(resp *Response[OK]) error {
		resp.SetMetadata(meta)
		return nil
	}
}

// Response is the result of executing a task. A handler reports the outcome by
// calling SetSuccess with a typed OK value or SetFailure with an error;
// binding encodes it into the receipt.
type Response[OK cbg.CBORMarshaler] struct {
	res execution.Response
}

// NewResponse creates a response for the given task, applying any options
// (such as [WithSuccess], [WithFailure], or [WithIssuer]) that set its outcome.
func NewResponse[OK cbg.CBORMarshaler](task cid.Cid, options ...ResponseOption[OK]) (*Response[OK], error) {
	xres, err := execution.NewResponse(task)
	if err != nil {
		return nil, err
	}
	response := Response[OK]{res: xres}
	for _, opt := range options {
		err := opt(&response)
		if err != nil {
			return nil, err
		}
	}
	return &response, nil
}

// Metadata returns the metadata container attached to the response, if any.
func (r *Response[OK]) Metadata() ucan.Container {
	return r.res.Metadata()
}

// Receipt returns the receipt recording the task's outcome, set by SetSuccess,
// SetFailure, or SetReceipt.
func (r *Response[OK]) Receipt() ucan.Receipt {
	return r.res.Receipt()
}

// SetFailure issues and sets a receipt reporting that the task failed with x.
func (r *Response[OK]) SetFailure(x error) error {
	return r.res.SetFailure(x)
}

// SetMetadata attaches a metadata container to the response.
func (r *Response[OK]) SetMetadata(meta ucan.Container) error {
	return r.res.SetMetadata(meta)
}

// SetReceipt sets a pre-built receipt as the task's outcome.
func (r *Response[OK]) SetReceipt(receipt ucan.Receipt) error {
	return r.res.SetReceipt(receipt)
}

// SetSuccess issues and sets a receipt reporting that the task succeeded with
// the typed result o.
func (r *Response[OK]) SetSuccess(o OK) error {
	return r.res.SetSuccess(o)
}

// HandlerFunc handles an invocation of a command: it reads typed arguments from
// the [Request] and reports the outcome on the [Response]. Register it with a
// server via [Binding.Handler], [NewHandler], or server.NewRoute.
type HandlerFunc[Args cbg.CBORUnmarshaler, OK cbg.CBORMarshaler] = func(*Request[Args], *Response[OK]) error

// NewHandler adapts a typed [HandlerFunc] into the untyped
// [execution.HandlerFunc] a server registers. It decodes the invocation's
// arguments into Args before calling handler, reporting a
// [MalformedArgumentsErrorName] failure if they do not conform.
func NewHandler[Args cbg.CBORUnmarshaler, OK cbg.CBORMarshaler](handler HandlerFunc[Args, OK]) execution.HandlerFunc {
	return func(req execution.Request, res execution.Response) error {
		inv := req.Invocation()
		task, err := NewTask[Args](inv.Subject(), inv.Command(), inv.ArgumentsBytes(), inv.Nonce())
		if err != nil {
			return res.SetFailure(NewMalformedArgumentsError(err))
		}
		return handler(&Request[Args]{Request: req, task: task}, &Response[OK]{res: res})
	}
}
