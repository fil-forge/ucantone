package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/dispatcher"
	"github.com/fil-forge/ucantone/principal"
	"github.com/fil-forge/ucantone/transport"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/validator"
)

type HTTPServer struct {
	id        principal.Signer
	executor  *dispatcher.Dispatcher
	codec     transport.InboundCodec[*http.Request, *http.Response]
	listeners []EventListener
}

// NewHTTP creates a new server capable of handling UCAN invocations over HTTP.
func NewHTTP(id principal.Signer, options ...HTTPOption) *HTTPServer {
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
		if reqDecodeListener, ok := listener.(RequestDecodeListener); ok {
			err := reqDecodeListener.OnRequestDecode(ctx, ct)
			if err != nil {
				errs = errors.Join(errs, err)
			}
		}
	}
	return errs
}

func (s *HTTPServer) emitResponseEncode(ctx context.Context, ct ucan.Container) error {
	var errs error
	for _, listener := range s.listeners {
		if resEncodeListener, ok := listener.(ResponseEncodeListener); ok {
			err := resEncodeListener.OnResponseEncode(ctx, ct)
			if err != nil {
				errs = errors.Join(errs, err)
			}
		}
	}
	return errs
}

func (s *HTTPServer) Handle(capability validator.Capability, fn execution.HandlerFunc) {
	s.executor.Handle(capability, fn)
}

func (s *HTTPServer) Execute(req execution.Request) (execution.Response, error) {
	return s.executor.Execute(req)
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

	var invocations []ucan.Invocation
	var delegations []ucan.Delegation
	var receipts []ucan.Receipt
	for _, inv := range reqContainer.Invocations() {
		aud := inv.Audience()
		if aud == nil {
			aud = inv.Subject()
		}
		// Skip invocations not addressed to this server.
		if aud.DID() != s.id.DID() {
			continue
		}
		req := execution.NewRequest(
			r.Context(),
			inv,
			execution.WithInvocations(reqContainer.Invocations()...),
			execution.WithDelegations(reqContainer.Delegations()...),
			execution.WithReceipts(reqContainer.Receipts()...),
		)

		res, err := s.executor.Execute(req)
		if err != nil {
			// This shouldn't really happen, executor only returns an error when
			// result or metadata cannot be set, which is likely a developer error.
			return nil, fmt.Errorf("executing task %s: %w", inv.Task().Link(), err)
		}

		receipts = append(receipts, res.Receipt())
		if res.Metadata() != nil {
			invocations = append(invocations, res.Metadata().Invocations()...)
			delegations = append(delegations, res.Metadata().Delegations()...)
			receipts = append(receipts, res.Metadata().Receipts()...)
		}
	}

	respContainer := container.New(
		container.WithInvocations(invocations...),
		container.WithDelegations(delegations...),
		container.WithReceipts(receipts...),
	)

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
