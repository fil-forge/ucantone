package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/execution/dispatcher"
	"github.com/fil-forge/ucantone/transport"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
)

type HTTPServer struct {
	id             ucan.Issuer
	executor       *dispatcher.Dispatcher
	codec          transport.InboundCodec[*http.Request, *http.Response]
	listeners      []EventListener
	maxConcurrency int
}

var (
	_ execution.Executor = (*HTTPServer)(nil)
	_ batch.Executor     = (*HTTPServer)(nil)
)

// NewHTTP creates a new server capable of handling UCAN invocations over HTTP.
func NewHTTP(id ucan.Issuer, options ...HTTPOption) *HTTPServer {
	cfg := httpServerConfig{
		codec:          transport.DefaultHTTPInboundCodec,
		maxConcurrency: DefaultMaxConcurrency,
	}
	for _, opt := range options {
		opt(&cfg)
	}
	dispatcherOpts := []dispatcher.Option{
		dispatcher.WithValidationOptions(cfg.validationOpts...),
		dispatcher.WithReceiptTimestamps(cfg.receiptTimestamps),
	}
	if cfg.panicLogger != nil {
		dispatcherOpts = append(dispatcherOpts, dispatcher.WithPanicLogger(cfg.panicLogger))
	}
	executor := dispatcher.New(id, dispatcherOpts...)
	return &HTTPServer{
		id:             id,
		codec:          cfg.codec,
		executor:       executor,
		listeners:      cfg.listeners,
		maxConcurrency: cfg.maxConcurrency,
	}
}

func (s *HTTPServer) emitRequestDecode(ctx context.Context, ct ucan.Container) error {
	var errs error
	for _, listener := range s.listeners {
		if err := listener.OnRequestDecode(ctx, ct); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func (s *HTTPServer) emitResponseEncode(ctx context.Context, ct ucan.Container) error {
	var errs error
	for _, listener := range s.listeners {
		if err := listener.OnResponseEncode(ctx, ct); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func (s *HTTPServer) Handle(command ucan.Command, fn execution.HandlerFunc) {
	s.executor.Handle(command, fn)
}

// Execute validates and executes a single invocation.
func (s *HTTPServer) Execute(req execution.Request) (execution.Response, error) {
	return s.executor.Execute(req)
}

// ExecuteBatch executes every invocation in the request that is addressed to
// this server and returns their receipts. Invocations addressed elsewhere are
// skipped and get no receipt. Each handler sees every token of
// the request as its metadata, and the tokens handlers attach to their
// responses are gathered into the metadata of the returned response.
//
// Invocations execute concurrently, each on its own goroutine, with at most
// [DefaultMaxConcurrency] of them running at once unless [WithMaxConcurrency]
// sets another cap. The cap applies to this request alone: concurrent
// requests each get their own, so the server as a whole runs up to the cap
// times the number of requests in flight. Handlers
// must therefore be safe to call concurrently within one request, as they
// already must be across requests. Receipts and metadata are gathered in
// request order once every invocation has finished, so the response does not
// depend on which handler finished first.
func (s *HTTPServer) ExecuteBatch(req *batch.Request) (*batch.Response, error) {
	// Every handler sees the same tokens, so the container is built once, on
	// the first invocation addressed to this server, and shared by every
	// handler in the batch.
	var execMeta ucan.Container

	// Each goroutine writes only its own slot, so the slice needs no lock and
	// the merge below runs in request order.
	results := make([]batchResult, len(req.Invocations()))
	var wg sync.WaitGroup
	var slots chan struct{}
	if s.maxConcurrency > 0 {
		slots = make(chan struct{}, s.maxConcurrency)
	}
	for i, inv := range req.Invocations() {
		aud := inv.Audience()
		if !aud.Defined() {
			aud = inv.Subject()
		}
		if aud != s.id.DID() {
			continue
		}
		if execMeta == nil {
			execMeta = batchMetadata(req)
		}
		// Acquire before spawning, so a request larger than the cap waits in
		// this loop instead of as a pile of blocked goroutines.
		if slots != nil {
			slots <- struct{}{}
		}
		wg.Go(func() {
			if slots != nil {
				defer func() { <-slots }()
			}
			execReq := execution.NewRequest(req.Context(), inv, execution.WithRequestMetadata(execMeta))
			res, err := s.executor.Execute(execReq)
			results[i] = batchResult{executed: true, response: res, err: err}
		})
	}
	wg.Wait()

	var errs error
	var receipts []ucan.Receipt
	var invocations []ucan.Invocation
	var delegations []ucan.Delegation
	var extraReceipts []ucan.Receipt
	for i, inv := range req.Invocations() {
		result := results[i]
		if !result.executed {
			continue
		}
		if result.err != nil {
			// This shouldn't really happen, executor only returns an error when
			// result or metadata cannot be set, which is likely a developer error.
			errs = errors.Join(errs, fmt.Errorf("executing task %s: %w", inv.Task().Link(), result.err))
			continue
		}
		receipts = append(receipts, result.response.Receipt())
		if result.response.Metadata() != nil {
			invocations = append(invocations, result.response.Metadata().Invocations()...)
			delegations = append(delegations, result.response.Metadata().Delegations()...)
			extraReceipts = append(extraReceipts, result.response.Metadata().Receipts()...)
		}
	}
	if errs != nil {
		return nil, errs
	}

	var options []batch.ResponseOption
	if len(invocations) > 0 || len(delegations) > 0 || len(extraReceipts) > 0 {
		options = append(options, batch.WithMetadata(container.New(
			container.WithInvocations(invocations...),
			container.WithDelegations(delegations...),
			container.WithReceipts(extraReceipts...),
		)))
	}
	return batch.NewResponse(receipts, options...), nil
}

// batchMetadata gathers every token of the batch request into one container.
func batchMetadata(req *batch.Request) ucan.Container {
	options := []container.Option{container.WithInvocations(req.Invocations()...)}
	if req.Metadata() != nil {
		options = append(options,
			container.WithInvocations(req.Metadata().Invocations()...),
			container.WithDelegations(req.Metadata().Delegations()...),
			container.WithReceipts(req.Metadata().Receipts()...),
		)
	}
	return container.New(options...)
}

// batchResult is the outcome of executing one invocation of a batch. executed
// is false for invocations addressed elsewhere, which get no receipt.
type batchResult struct {
	executed bool
	response execution.Response
	err      error
}

func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := s.RoundTrip(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("handling request: %v", err), http.StatusInternalServerError)
		return
	}
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	resp.Body.Close()
}

// RoundTrip unpacks and executes an incoming request, returning the response.
func (s *HTTPServer) RoundTrip(r *http.Request) (*http.Response, error) {
	reqContainer, err := s.codec.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("decoding request: %w", err)
	}
	err = s.emitRequestDecode(r.Context(), reqContainer)
	if err != nil {
		return nil, fmt.Errorf("emitting request decode event: %w", err)
	}

	res, err := s.ExecuteBatch(batch.NewRequest(
		r.Context(),
		reqContainer.Invocations(),
		batch.WithDelegations(reqContainer.Delegations()...),
		batch.WithReceipts(reqContainer.Receipts()...),
	))
	if err != nil {
		return nil, err
	}

	var receipts []ucan.Receipt
	for _, inv := range reqContainer.Invocations() {
		if rcpt, ok := res.Receipt(inv.Task().Link()); ok {
			receipts = append(receipts, rcpt)
		}
	}
	options := []container.Option{container.WithReceipts(receipts...)}
	if res.Metadata() != nil {
		options = append(options,
			container.WithInvocations(res.Metadata().Invocations()...),
			container.WithDelegations(res.Metadata().Delegations()...),
			container.WithReceipts(res.Metadata().Receipts()...),
		)
	}
	respContainer := container.New(options...)

	err = s.emitResponseEncode(r.Context(), respContainer)
	if err != nil {
		return nil, fmt.Errorf("emitting response encode event: %w", err)
	}
	resp, err := s.codec.Encode(respContainer)
	if err != nil {
		return nil, fmt.Errorf("encoding response container: %w", err)
	}

	return resp, nil
}
