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
	listeners         []EventListener
	panicLogger       dispatcher.PanicLogger
}

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
// requests and responses as they are decoded and encoded.
func WithEventListener(listener EventListener) HTTPOption {
	return func(cfg *httpServerConfig) {
		cfg.listeners = append(cfg.listeners, listener)
	}
}
