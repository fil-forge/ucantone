package execution

import (
	"context"

	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
)

type requestConfig struct {
	invocations []ucan.Invocation
	delegations []ucan.Delegation
	receipts    []ucan.Receipt
	metadata    ucan.Container
}

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

// WithRequestMetadata sets a ready-made container as the request metadata, so
// an executor running many invocations against the same tokens builds the
// container once and shares it.
//
// The container is shared by every request it is passed to, and
// [container.Container] returns its internal slices. Handlers must treat the
// metadata as read-only and clone a slice before modifying it.
//
// Tokens given through [WithInvocations], [WithDelegations] and [WithReceipts]
// are merged into a new container after the tokens of this one, de-duplicated
// by CID. The given container is used as is only when no token option is
// passed.
func WithRequestMetadata(metadata ucan.Container) RequestOption {
	return func(cfg *requestConfig) {
		cfg.metadata = metadata
	}
}

type ExecRequest struct {
	ctx        context.Context
	invocation ucan.Invocation
	metadata   ucan.Container
}

func NewRequest(ctx context.Context, inv ucan.Invocation, options ...RequestOption) *ExecRequest {
	cfg := requestConfig{}
	for _, opt := range options {
		opt(&cfg)
	}
	return &ExecRequest{
		ctx:        ctx,
		invocation: inv,
		metadata:   resolveMetadata(&cfg),
	}
}

func resolveMetadata(cfg *requestConfig) ucan.Container {
	hasTokens := len(cfg.invocations) > 0 || len(cfg.delegations) > 0 || len(cfg.receipts) > 0
	if !hasTokens {
		return cfg.metadata
	}
	var options []container.Option
	if cfg.metadata != nil {
		options = append(options,
			container.WithInvocations(cfg.metadata.Invocations()...),
			container.WithDelegations(cfg.metadata.Delegations()...),
			container.WithReceipts(cfg.metadata.Receipts()...),
		)
	}
	options = append(options,
		container.WithInvocations(cfg.invocations...),
		container.WithDelegations(cfg.delegations...),
		container.WithReceipts(cfg.receipts...),
	)
	return container.New(options...)
}

func (r *ExecRequest) Context() context.Context {
	return r.ctx
}

func (r *ExecRequest) Invocation() ucan.Invocation {
	return r.invocation
}

func (r *ExecRequest) Metadata() ucan.Container {
	return r.metadata
}
