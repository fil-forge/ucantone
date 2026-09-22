package server

import (
	"log/slog"
	"net/http"

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
	logger            *slog.Logger
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

// WithLogger sets the logger the server reports recovered handler panics to.
// Defaults to [slog.Default]. A nil logger panics.
func WithLogger(logger *slog.Logger) HTTPOption {
	if logger == nil {
		panic("server.WithLogger: logger must not be nil")
	}
	return func(cfg *httpServerConfig) {
		cfg.logger = logger
	}
}

// WithEventListener registers an [EventListener] to observe the server's
// requests and responses as they are decoded and encoded.
func WithEventListener(listener EventListener) HTTPOption {
	return func(cfg *httpServerConfig) {
		cfg.listeners = append(cfg.listeners, listener)
	}
}
