package bind

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

type Request[Args cbg.CBORUnmarshaler] struct {
	execution.Request
	task *Task[Args]
}

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

type SignerSetter interface {
	SetSigner(ucan.Signer) error
}

type ResponseOption[OK cbg.CBORMarshaler] func(r *Response[OK]) error

func WithSigner[OK cbg.CBORMarshaler](signer ucan.Signer) ResponseOption[OK] {
	return func(resp *Response[OK]) error {
		setter, ok := resp.res.(SignerSetter)
		if !ok {
			return fmt.Errorf("cannot set signer: underlying response is not a signer setter")
		}
		return setter.SetSigner(signer)
	}
}

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

func WithMetadata[OK cbg.CBORMarshaler](meta ucan.Container) ResponseOption[OK] {
	return func(resp *Response[OK]) error {
		resp.SetMetadata(meta)
		return nil
	}
}

type Response[OK cbg.CBORMarshaler] struct {
	res execution.Response
}

// NewResponse creates a new response object, representing the result of
// executing a task.
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

func (r *Response[OK]) Metadata() ucan.Container {
	return r.res.Metadata()
}

func (r *Response[OK]) Receipt() ucan.Receipt {
	return r.res.Receipt()
}

func (r *Response[OK]) SetFailure(x error) error {
	return r.res.SetFailure(x)
}

func (r *Response[OK]) SetMetadata(meta ucan.Container) error {
	return r.res.SetMetadata(meta)
}

func (r *Response[OK]) SetReceipt(receipt ucan.Receipt) error {
	return r.res.SetReceipt(receipt)
}

func (r *Response[OK]) SetSuccess(o OK) error {
	return r.res.SetSuccess(o)
}

type HandlerFunc[Args cbg.CBORUnmarshaler, OK cbg.CBORMarshaler] = func(*Request[Args], *Response[OK]) error

// NewHandler creates a new [execution.HandlerFunc] from the provided typed
// handler.
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
