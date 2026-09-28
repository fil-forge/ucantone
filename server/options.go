package server

import (
	"net/http"

	"github.com/fil-forge/ucantone/execution/dispatcher"
	"github.com/fil-forge/ucantone/transport"
	"github.com/fil-forge/ucantone/validator"
)

// HTTPOption is an option configuring a UCAN HTTP server.
type HTTPOption func(cfg *httpServerConfig)

type httpServerConfig struct {
	codec             transport.InboundCodec[*http.Request, *http.Response]
	validationOpts    []validator.Option
	receiptTimestamps bool
	listeners         []listenerEntry
	panicLogger       dispatcher.PanicLogger
	maxConcurrency    int
}

// DefaultMaxConcurrency is how many invocations of one request execute at the
// same time unless [WithMaxConcurrency] says otherwise. It is the value
// quic-go uses for MaxIncomingStreams and the floor RFC 9113 recommends for
// SETTINGS_MAX_CONCURRENT_STREAMS; x/net/http2 defaults to 250.
const DefaultMaxConcurrency = 100

func WithHTTPCodec(codec transport.InboundCodec[*http.Request, *http.Response]) HTTPOption {
	return func(cfg *httpServerConfig) {
		cfg.codec = codec
	}
}

func WithValidationOptions(options ...validator.Option) HTTPOption {
	return func(cfg *httpServerConfig) {
		cfg.validationOpts = append(cfg.validationOpts, options...)
	}
}

// WithReceiptTimestamps configures the server to issue receipts with
// issuance timestamps or not.
func WithReceiptTimestamps(enabled bool) HTTPOption {
	return func(cfg *httpServerConfig) {
		cfg.receiptTimestamps = enabled
	}
}

// WithMaxConcurrency caps how many invocations of one request execute at the
// same time. Every invocation still gets its own goroutine; the cap is a
// per-request semaphore that limits how many are admitted at once, the way an
// HTTP/2 or QUIC server caps concurrent streams per connection. It does not
// limit the server as a whole: each request in flight gets its own cap.
//
// - WithMaxConcurrency(1) runs the invocations of a request serially, one after another.
// - WithMaxConcurrency(0) removes the cap.
// - A negative value panics.
//
// Defaults to [DefaultMaxConcurrency].
func WithMaxConcurrency(n int) HTTPOption {
	if n < 0 {
		panic("server.WithMaxConcurrency: n must not be negative")
	}
	return func(cfg *httpServerConfig) {
		cfg.maxConcurrency = n
	}
}

// WithPanicLogger sets the function the server's dispatcher records recovered
// panics with, from handlers and from validation code alike. See
// [dispatcher.WithPanicLogger] for the default and the contract. A nil logger
// panics.
func WithPanicLogger(logger dispatcher.PanicLogger) HTTPOption {
	if logger == nil {
		panic("server.WithPanicLogger: logger must not be nil")
	}
	return func(cfg *httpServerConfig) {
		cfg.panicLogger = logger
	}
}

// WithEventListener registers an [EventListener] to observe the server's
// requests and responses as they are decoded and encoded. Its OnRequestDecode
// runs before any handler does, so an error from it fails the request before
// anything executes: the place for a listener that gates execution.
func WithEventListener(listener EventListener) HTTPOption {
	return func(cfg *httpServerConfig) {
		cfg.listeners = append(cfg.listeners, listenerEntry{EventListener: listener})
	}
}

// WithConcurrentEventListener registers an [EventListener] whose
// OnRequestDecode runs on its own goroutine while the request's handlers
// execute, instead of before them. The server waits for it before any
// OnResponseEncode runs, so whatever it records is in place by the time the
// response leaves, and an error from it still fails the request, after the
// handlers have run. Its OnResponseEncode runs as it does for
// [WithEventListener]. The place for a listener that only observes the
// request, such as one that stores it, and whose work would otherwise delay
// every handler by its own duration.
func WithConcurrentEventListener(listener EventListener) HTTPOption {
	return func(cfg *httpServerConfig) {
		cfg.listeners = append(cfg.listeners, listenerEntry{EventListener: listener, concurrent: true})
	}
}

// listenerEntry is a registered listener and how its OnRequestDecode runs.
// One list keeps registration order for OnResponseEncode, which runs the same
// way for every listener.
type listenerEntry struct {
	EventListener
	concurrent bool
}
