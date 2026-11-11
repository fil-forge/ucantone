package client

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/transport"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
)

type Client[Req transport.Request, Res any] struct {
	Codec     transport.OutboundCodec[Req, Res]
	Transport transport.RoundTripper[Req, Res]
	Listeners []EventListener
}

func New[Req transport.Request, Res any](transport transport.RoundTripper[Req, Res], codec transport.OutboundCodec[Req, Res]) *Client[Req, Res] {
	return &Client[Req, Res]{
		Transport: transport,
		Codec:     codec,
	}
}

func (c *Client[Req, Res]) emitRequestEncode(ctx context.Context, ct ucan.Container) error {
	var errs error
	for _, listener := range c.Listeners {
		if err := listener.OnRequestEncode(ctx, ct); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func (c *Client[Req, Res]) emitResponseDecode(ctx context.Context, ct ucan.Container) error {
	var errs error
	for _, listener := range c.Listeners {
		if err := listener.OnResponseDecode(ctx, ct); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

// Execute sends a single invocation and returns the receipt for its task. It is
// a batch of one; see [Client.ExecuteBatch].
func (c *Client[Req, Res]) Execute(execRequest execution.Request) (execution.Response, error) {
	return executeOne(c, execRequest)
}

// ExecuteBatch sends every invocation in the request in one round trip and
// returns their receipts. The response is an error if the executor did not
// answer one of the invocations.
func (c *Client[Req, Res]) ExecuteBatch(req *batch.Request) (_ *batch.Response, err error) {
	if len(req.Invocations()) == 0 {
		return nil, errors.New("no invocations to execute")
	}
	invocations := req.Invocations()
	var delegations []ucan.Delegation
	var receipts []ucan.Receipt
	if req.Metadata() != nil {
		invocations = append(invocations, req.Metadata().Invocations()...)
		delegations = append(delegations, req.Metadata().Delegations()...)
		receipts = append(receipts, req.Metadata().Receipts()...)
	}
	reqContainer := container.New(
		container.WithInvocations(invocations...),
		container.WithDelegations(delegations...),
		container.WithReceipts(receipts...),
	)
	err = c.emitRequestEncode(req.Context(), reqContainer)
	if err != nil {
		return nil, fmt.Errorf("emitting request encode event: %w", err)
	}
	request, err := c.Codec.Encode(req.Context(), reqContainer)
	if err != nil {
		return nil, fmt.Errorf("encoding container: %w", err)
	}
	response, err := c.Transport.RoundTrip(request)
	if err != nil {
		return nil, fmt.Errorf("roundtripping request: %w", err)
	}
	resContainer, err := c.Codec.Decode(response)
	if err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	// The decoded container owns a live response body until something closes
	// it. On the way out with an error the caller never sees the container and
	// so cannot close it — and a batch carrying an invocation addressed
	// elsewhere reaches exactly that path by design — so release it here.
	// A successful return hands the container to the caller to close.
	defer func() {
		if err != nil {
			if closer, ok := resContainer.(io.Closer); ok {
				_ = closer.Close()
			}
		}
	}()

	err = c.emitResponseDecode(req.Context(), resContainer)
	if err != nil {
		return nil, fmt.Errorf("emitting response decode event: %w", err)
	}
	// Indexed once rather than scanned per invocation: the container's own
	// lookup is linear, which would make a batch quadratic in its own size.
	answered := batch.NewResponse(resContainer.Receipts())
	rcpts := make([]ucan.Receipt, 0, len(req.Invocations()))
	for _, inv := range req.Invocations() {
		task := inv.Task().Link()
		rcpt, ok := answered.Receipt(task)
		if !ok {
			return nil, fmt.Errorf("missing receipt for task: %s", task)
		}
		rcpts = append(rcpts, rcpt)
	}
	return batch.NewResponse(rcpts, batch.WithMetadata(resContainer)), nil
}

// executeOne runs a single invocation as a batch of one through the given
// executor and adapts the result to an [execution.Response].
func executeOne(executor batch.Executor, execRequest execution.Request) (execution.Response, error) {
	var options []batch.RequestOption
	if meta := execRequest.Metadata(); meta != nil {
		options = append(options,
			batch.WithInvocations(meta.Invocations()...),
			batch.WithDelegations(meta.Delegations()...),
			batch.WithReceipts(meta.Receipts()...),
		)
	}
	inv := execRequest.Invocation()
	res, err := executor.ExecuteBatch(batch.NewRequest(execRequest.Context(), []ucan.Invocation{inv}, options...))
	if err != nil {
		return nil, err
	}
	task := inv.Task().Link()
	rcpt, ok := res.Receipt(task)
	if !ok {
		return nil, fmt.Errorf("missing receipt for task: %s", task)
	}
	return execution.NewResponse(
		task,
		execution.WithReceipt(rcpt),
		execution.WithMetadata(res.Metadata()),
	)
}
