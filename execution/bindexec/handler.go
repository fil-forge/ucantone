package bindexec

import (
	"context"
	"fmt"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

type Arguments interface {
	dagcbor.Unmarshaler
}

type Success interface {
	dagcbor.Marshaler
}

type requestConfig struct {
	invocations []ucan.Invocation
	delegations []ucan.Delegation
	receipts    []ucan.Receipt
}

type RequestOption = func(cfg *requestConfig)

// WithProofs adds delegations to the execution request. They should be linked
// from the invocation to be executed.
func WithProofs(delegations ...ucan.Delegation) RequestOption {
	return func(cfg *requestConfig) {
		cfg.delegations = append(cfg.delegations, delegations...)
	}
}

// WithDelegations adds delegations to the execution request.
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

type Request[A Arguments] struct {
	execution.Request
	task *Task[A]
}

func NewRequest[A Arguments](ctx context.Context, inv ucan.Invocation, options ...RequestOption) (*Request[A], error) {
	cfg := requestConfig{}
	for _, opt := range options {
		opt(&cfg)
	}
	task, err := NewTask[A](inv.Subject(), inv.Command(), inv.ArgumentsBytes(), inv.Nonce())
	if err != nil {
		return nil, err
	}
	return &Request[A]{
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
func (r *Request[A]) Task() *Task[A] {
	return r.task
}

type SignerSetter interface {
	SetSigner(ucan.Signer) error
}

type ResponseOption[O Success] func(r *Response[O]) error

func WithSigner[O Success](signer ucan.Signer) ResponseOption[O] {
	return func(resp *Response[O]) error {
		setter, ok := resp.res.(SignerSetter)
		if !ok {
			return fmt.Errorf("cannot set signer: underlying response is not a signer setter")
		}
		return setter.SetSigner(signer)
	}
}

func WithReceipt[O Success](receipt ucan.Receipt) ResponseOption[O] {
	return func(resp *Response[O]) error {
		resp.SetReceipt(receipt)
		return nil
	}
}

// WithSuccess issues and sets a receipt for a successful execution of a task.
func WithSuccess[O Success](o O) ResponseOption[O] {
	return func(resp *Response[O]) error {
		return resp.SetSuccess(o)
	}
}

// WithFailure issues and sets a receipt for a failed execution of a task.
func WithFailure[O Success](signer ucan.Signer, task cid.Cid, x error) ResponseOption[O] {
	return func(resp *Response[O]) error {
		return resp.SetFailure(x)
	}
}

func WithMetadata[O Success](meta ucan.Container) ResponseOption[O] {
	return func(resp *Response[O]) error {
		resp.SetMetadata(meta)
		return nil
	}
}

type Response[O Success] struct {
	res execution.Response
}

// NewResponse creates a new response object, representing the result of
// executing a task.
func NewResponse[O Success](task cid.Cid, options ...ResponseOption[O]) (*Response[O], error) {
	xres, err := execution.NewResponse(task)
	if err != nil {
		return nil, err
	}
	response := Response[O]{res: xres}
	for _, opt := range options {
		err := opt(&response)
		if err != nil {
			return nil, err
		}
	}
	return &response, nil
}

func (r *Response[O]) Metadata() ucan.Container {
	return r.res.Metadata()
}

func (r *Response[O]) Receipt() ucan.Receipt {
	return r.res.Receipt()
}

func (r *Response[O]) SetFailure(x error) error {
	return r.res.SetFailure(x)
}

func (r *Response[O]) SetMetadata(meta ucan.Container) error {
	return r.res.SetMetadata(meta)
}

func (r *Response[O]) SetReceipt(receipt ucan.Receipt) error {
	return r.res.SetReceipt(receipt)
}

func (r *Response[O]) SetSuccess(o O) error {
	return r.res.SetSuccess(o)
}

type HandlerFunc[A Arguments, O Success] = func(*Request[A], *Response[O]) error

// NewHandler creates a new [execution.HandlerFunc] from the provided typed
// handler.
func NewHandler[A Arguments, O Success](handler HandlerFunc[A, O]) execution.HandlerFunc {
	return func(req execution.Request, res execution.Response) error {
		inv := req.Invocation()
		task, err := NewTask[A](inv.Subject(), inv.Command(), inv.ArgumentsBytes(), inv.Nonce())
		if err != nil {
			return res.SetFailure(NewMalformedArgumentsError(err))
		}
		return handler(&Request[A]{Request: req, task: task}, &Response[O]{res: res})
	}
}

