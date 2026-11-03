package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
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
	listeners      []listenerEntry
	listenerPanics ListenerPanicLogger
}

var (
	_ execution.Executor = (*HTTPServer)(nil)
	_ batch.Executor     = (*HTTPServer)(nil)
)

// NewHTTP creates a new server capable of handling UCAN invocations over HTTP.
func NewHTTP(id ucan.Issuer, options ...HTTPOption) *HTTPServer {
	cfg := httpServerConfig{
		codec:          transport.DefaultHTTPInboundCodec,
		listenerPanics: logListenerPanic,
		maxConcurrency: DefaultMaxConcurrency,
	}
	for _, opt := range options {
		opt(&cfg)
	}
	dispatcherOpts := []dispatcher.Option{
		dispatcher.WithValidationOptions(cfg.validationOpts...),
		dispatcher.WithReceiptTimestamps(cfg.receiptTimestamps),
		dispatcher.WithMaxConcurrency(cfg.maxConcurrency),
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
		listenerPanics: cfg.listenerPanics,
	}
}

// emitRequestDecode calls OnRequestDecode of every listener registered with
// [WithEventListener], before any handler runs.
func (s *HTTPServer) emitRequestDecode(ctx context.Context, ct ucan.Container) error {
	var errs error
	for _, listener := range s.listeners {
		if listener.concurrent {
			continue
		}
		if err := listener.OnRequestDecode(ctx, ct); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

// startRequestDecode calls OnRequestDecode of every listener registered with
// [WithConcurrentEventListener], each on its own goroutine, and returns a
// function that waits for them all and reports their errors. The function is
// safe to call more than once. A panic in a listener becomes an error: unlike
// a listener called from ServeHTTP, a goroutine has no net/http recovery
// boundary above it.
func (s *HTTPServer) startRequestDecode(ctx context.Context, ct ucan.Container) func() error {
	var wg sync.WaitGroup
	errs := make([]error, len(s.listeners))
	for i, listener := range s.listeners {
		if !listener.concurrent {
			continue
		}
		wg.Go(func() {
			errs[i] = s.requestDecode(ctx, listener, ct)
		})
	}
	return func() error {
		wg.Wait()
		return errors.Join(errs...)
	}
}

// errListenerPanic is what a panicking listener fails the request with. It
// says nothing about the panic itself: the error reaches the HTTP caller, and
// the value goes to the [ListenerPanicLogger] alone.
var errListenerPanic = errors.New("event listener panicked")

// requestDecode calls the listener, turning a panic into [errListenerPanic]
// after recording it.
func (s *HTTPServer) requestDecode(ctx context.Context, listener RequestDecodeListener, ct ucan.Container) (err error) {
	// recover() alone cannot tell a normal return from panic(nil), so the
	// flag is what says whether the listener returned.
	returned := false
	defer func() {
		if returned {
			return
		}
		s.listenerPanics(ct, recover())
		err = errListenerPanic
	}()
	err = listener.OnRequestDecode(ctx, ct)
	returned = true
	return err
}

// logListenerPanic is the default [ListenerPanicLogger]. It prints the panic
// and the stack through the standard log package, as the dispatcher's default
// does for handler panics.
func logListenerPanic(_ ucan.Container, value any) {
	buf := make([]byte, panicStackSize)
	buf = buf[:runtime.Stack(buf, false)]
	log.Printf("panic in event listener: %v\n%s", value, buf)
}

// panicStackSize matches the buffer net/http uses for the same purpose.
const panicStackSize = 64 << 10

// emitResponseEncode calls OnResponseEncode of every listener, however it was
// registered, in registration order.
func (s *HTTPServer) emitResponseEncode(ctx context.Context, ct ucan.Container) error {
	var errs error
	for _, listener := range s.listeners {
		if err := listener.OnResponseEncode(ctx, ct); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

// Handle registers the handler that executes invocations of command, one call
// per invocation. A batch handler registered for the same command with
// [HTTPServer.HandleBatch] takes precedence over it. A nil handler panics.
func (s *HTTPServer) Handle(command ucan.Command, fn execution.HandlerFunc) {
	s.executor.Handle(command, fn)
}

// HandleBatch registers the handler that executes every invocation of command
// in a request with one call. It is always used for the command when
// registered, even for a request with a single invocation of it, and takes
// precedence over a handler registered with [HTTPServer.Handle]. A nil handler
// panics.
func (s *HTTPServer) HandleBatch(command ucan.Command, fn execution.BatchHandlerFunc) {
	s.executor.HandleBatch(command, fn)
}

// HandleRoute registers the route's handler. A route with a BatchHandler is
// registered with [HTTPServer.HandleBatch] and its Handler is not registered,
// since the batch handler takes precedence; any other route is registered with
// [HTTPServer.Handle]. A route with neither handler panics.
func (s *HTTPServer) HandleRoute(route Route) {
	switch {
	case route.BatchHandler != nil:
		s.HandleBatch(route.Command, route.BatchHandler)
	case route.Handler != nil:
		s.Handle(route.Command, route.Handler)
	default:
		panic(fmt.Sprintf("server.HandleRoute: route for %q has no handler", route.Command))
	}
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
// Invocations of a command with a batch handler ([HTTPServer.HandleBatch]) are
// validated one by one and the valid ones go to the batch handler in one call
// per command. Every other invocation runs through its own handler.
//
// Validations and handler calls execute concurrently, each on its own
// goroutine, with at most [DefaultMaxConcurrency] of them running at once
// unless [WithMaxConcurrency] sets another cap. A batch handler call takes one
// slot. The cap applies to this request alone: concurrent requests each get
// their own, so the server as a whole runs up to the cap times the number of
// requests in flight. Handlers must therefore be safe to call concurrently
// within one request, as they already must be across requests. Receipts and
// metadata are gathered in request order once every invocation has finished,
// so the response does not depend on which handler finished first.
func (s *HTTPServer) ExecuteBatch(req *batch.Request) (*batch.Response, error) {
	var addressed []ucan.Invocation
	for _, inv := range req.Invocations() {
		aud := inv.Audience()
		if !aud.Defined() {
			aud = inv.Subject()
		}
		if aud == s.id.DID() {
			addressed = append(addressed, inv)
		}
	}

	var execReqs []execution.Request
	if len(addressed) > 0 {
		// Every handler sees the same tokens, so the container is built once
		// and shared by every handler in the batch.
		execMeta := batchMetadata(req)
		execReqs = make([]execution.Request, len(addressed))
		for i, inv := range addressed {
			execReqs[i] = execution.NewRequest(req.Context(), inv, execution.WithRequestMetadata(execMeta))
		}
	}
	// The dispatcher only returns an error when a response cannot be built,
	// which is likely a developer error.
	responses, err := s.executor.ExecuteAll(execReqs)
	if err != nil {
		return nil, err
	}

	var receipts []ucan.Receipt
	var invocations []ucan.Invocation
	var delegations []ucan.Delegation
	var extraReceipts []ucan.Receipt
	for _, res := range responses {
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
	// The concurrent listeners observe the request while its invocations
	// execute. Every return path waits for them, the error paths included:
	// the request context is cancelled once ServeHTTP returns, and a listener
	// still running would see its work fail under it.
	awaitRequestDecode := s.startRequestDecode(r.Context(), reqContainer)
	defer awaitRequestDecode()

	res, err := s.ExecuteBatch(batch.NewRequest(
		r.Context(),
		reqContainer.Invocations(),
		batch.WithDelegations(reqContainer.Delegations()...),
		batch.WithReceipts(reqContainer.Receipts()...),
	))
	if err != nil {
		// The listeners' errors are reported too, not just waited for.
		return nil, errors.Join(err, awaitRequestDecode())
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

	// The response listeners run once the request is fully recorded, so a
	// listener that stores both halves sees them land in order.
	if err := awaitRequestDecode(); err != nil {
		return nil, fmt.Errorf("emitting request decode event: %w", err)
	}
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
