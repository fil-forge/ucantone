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
	metadataSet bool
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

// WithMetadataContainer sets a ready-made container as the request metadata,
// so an executor running many invocations against the same tokens builds the
// container once and shares it. It cannot be combined with [WithInvocations],
// [WithDelegations] or [WithReceipts]: [NewRequest] panics when both are given.
func WithMetadataContainer(metadata ucan.Container) RequestOption {
	return func(cfg *requestConfig) {
		cfg.metadata = metadata
		cfg.metadataSet = true
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
	meta := cfg.metadata
	hasTokens := len(cfg.invocations) > 0 || len(cfg.delegations) > 0 || len(cfg.receipts) > 0
	if cfg.metadataSet && hasTokens {
		panic("execution.NewRequest: WithMetadataContainer cannot be combined with WithInvocations, WithDelegations or WithReceipts")
	}
	if !cfg.metadataSet && hasTokens {
		meta = container.New(
			container.WithInvocations(cfg.invocations...),
			container.WithDelegations(cfg.delegations...),
			container.WithReceipts(cfg.receipts...),
		)
	}
	return &ExecRequest{
		ctx:        ctx,
		invocation: inv,
		metadata:   meta,
	}
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
