// Package batch executes many UCAN invocations in one round trip.
//
// A request container carries any number of invocations, and an executor runs
// every one that is addressed to it, answering each with its own receipt. A
// [Request] lists the invocations the caller wants executed together with the
// tokens that travel alongside them (proofs, receipts, context invocations),
// and a [Response] holds the receipts keyed by the task they ran.
//
// The single-invocation API in the execution package is a special case of
// this one: a batch of one.
package batch

import (
	"context"

	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/ipfs/go-cid"
)

// Executor executes every invocation in a [Request] that is addressed to it in
// one round trip and answers each with a receipt.
type Executor interface {
	ExecuteBatch(*Request) (*Response, error)
}

type requestConfig struct {
	invocations []ucan.Invocation
	delegations []ucan.Delegation
	receipts    []ucan.Receipt
}

type RequestOption func(cfg *requestConfig)

// WithDelegations adds delegations to the request. They should be linked from
// the invocations to be executed.
func WithDelegations(delegations ...ucan.Delegation) RequestOption {
	return func(cfg *requestConfig) {
		cfg.delegations = append(cfg.delegations, delegations...)
	}
}

// WithReceipts adds receipts to the request.
func WithReceipts(receipts ...ucan.Receipt) RequestOption {
	return func(cfg *requestConfig) {
		cfg.receipts = append(cfg.receipts, receipts...)
	}
}

// WithInvocations adds invocations that travel with the request as context
// (a cause, a claim) rather than as part of the batch. Note that an executor
// still executes any of them addressed to it; list an invocation in the batch
// itself when its receipt is wanted.
func WithInvocations(invocations ...ucan.Invocation) RequestOption {
	return func(cfg *requestConfig) {
		cfg.invocations = append(cfg.invocations, invocations...)
	}
}

// Request is a set of invocations to execute in one round trip, plus the
// tokens that travel with them.
type Request struct {
	ctx         context.Context
	invocations []ucan.Invocation
	metadata    ucan.Container
}

// NewRequest creates a request to execute the given invocations. Options add
// the tokens that accompany them.
func NewRequest(ctx context.Context, invocations []ucan.Invocation, options ...RequestOption) *Request {
	cfg := requestConfig{}
	for _, opt := range options {
		opt(&cfg)
	}
	var meta ucan.Container
	if len(cfg.invocations) > 0 || len(cfg.delegations) > 0 || len(cfg.receipts) > 0 {
		meta = container.New(
			container.WithInvocations(cfg.invocations...),
			container.WithDelegations(cfg.delegations...),
			container.WithReceipts(cfg.receipts...),
		)
	}
	return &Request{
		ctx:         ctx,
		invocations: invocations,
		metadata:    meta,
	}
}

func (r *Request) Context() context.Context {
	return r.ctx
}

// Invocations that should be executed. The caller expects a receipt for each.
func (r *Request) Invocations() []ucan.Invocation {
	return r.invocations
}

// Metadata provides additional tokens that travel with the invocations, or nil
// when there are none.
func (r *Request) Metadata() ucan.Container {
	return r.metadata
}

// Response holds one receipt per executed task.
type Response struct {
	receipts []ucan.Receipt
	byTask   map[cid.Cid]ucan.Receipt
	metadata ucan.Container
}

type ResponseOption func(r *Response)

// WithMetadata sets additional tokens the executor returned alongside the
// receipts.
func WithMetadata(m ucan.Container) ResponseOption {
	return func(r *Response) {
		r.metadata = m
	}
}

// NewResponse creates a response holding the given receipts, in the order the
// tasks were executed. When two receipts share a task, the first one is the
// one [Response.Receipt] returns.
func NewResponse(receipts []ucan.Receipt, options ...ResponseOption) *Response {
	byTask := make(map[cid.Cid]ucan.Receipt, len(receipts))
	for _, rcpt := range receipts {
		if _, ok := byTask[rcpt.Ran()]; !ok {
			byTask[rcpt.Ran()] = rcpt
		}
	}
	r := &Response{receipts: receipts, byTask: byTask}
	for _, opt := range options {
		opt(r)
	}
	return r
}

// Receipt retrieves the receipt for the given task.
func (r *Response) Receipt(task cid.Cid) (ucan.Receipt, bool) {
	rcpt, ok := r.byTask[task]
	return rcpt, ok
}

// Receipts for every executed task, in the order the tasks were executed.
func (r *Response) Receipts() []ucan.Receipt {
	return r.receipts
}

// Metadata provides additional tokens the executor returned, or nil when
// there are none.
func (r *Response) Metadata() ucan.Container {
	return r.metadata
}
