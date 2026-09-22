package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/execution/dispatcher"
	"github.com/fil-forge/ucantone/transport"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
)

type HTTPServer struct {
	id        ucan.Issuer
	executor  *dispatcher.Dispatcher
	codec     transport.InboundCodec[*http.Request, *http.Response]
	listeners []EventListener
}

var (
	_ execution.Executor = (*HTTPServer)(nil)
	_ batch.Executor     = (*HTTPServer)(nil)
)

// NewHTTP creates a new server capable of handling UCAN invocations over HTTP.
func NewHTTP(id ucan.Issuer, options ...HTTPOption) *HTTPServer {
	cfg := httpServerConfig{
		codec: transport.DefaultHTTPInboundCodec,
	}
	for _, opt := range options {
		opt(&cfg)
	}
	executor := dispatcher.New(
		id,
		dispatcher.WithValidationOptions(cfg.validationOpts...),
		dispatcher.WithReceiptTimestamps(cfg.receiptTimestamps),
	)
	return &HTTPServer{
		id:        id,
		codec:     cfg.codec,
		executor:  executor,
		listeners: cfg.listeners,
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
func (s *HTTPServer) ExecuteBatch(req *batch.Request) (*batch.Response, error) {
	var metaInvocations []ucan.Invocation
	var metaDelegations []ucan.Delegation
	var metaReceipts []ucan.Receipt
	if req.Metadata() != nil {
		metaInvocations = req.Metadata().Invocations()
		metaDelegations = req.Metadata().Delegations()
		metaReceipts = req.Metadata().Receipts()
	}

	// Every handler sees the same tokens, so the container is built once for
	// the whole batch rather than once per invocation.
	var execMeta ucan.Container
	if len(req.Invocations()) > 0 || len(metaInvocations) > 0 || len(metaDelegations) > 0 || len(metaReceipts) > 0 {
		execMeta = container.New(
			container.WithInvocations(req.Invocations()...),
			container.WithInvocations(metaInvocations...),
			container.WithDelegations(metaDelegations...),
			container.WithReceipts(metaReceipts...),
		)
	}

	var receipts []ucan.Receipt
	var invocations []ucan.Invocation
	var delegations []ucan.Delegation
	var extraReceipts []ucan.Receipt
	for _, inv := range req.Invocations() {
		aud := inv.Audience()
		if !aud.Defined() {
			aud = inv.Subject()
		}
		if aud != s.id.DID() {
			continue
		}
		execReq := execution.NewRequest(req.Context(), inv, execution.WithMetadataContainer(execMeta))

		res, err := s.executor.Execute(execReq)
		if err != nil {
			// This shouldn't really happen, executor only returns an error when
			// result or metadata cannot be set, which is likely a developer error.
			return nil, fmt.Errorf("executing task %s: %w", inv.Task().Link(), err)
		}

		receipts = append(receipts, res.Receipt())
		if res.Metadata() != nil {
			invocations = append(invocations, res.Metadata().Invocations()...)
			delegations = append(delegations, res.Metadata().Delegations()...)
			extraReceipts = append(extraReceipts, res.Metadata().Receipts()...)
		}
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
