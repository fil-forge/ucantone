package server

import (
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

// WithEventListener adds an event listener to the HTTP server for monitoring
// requests and responses.
func WithEventListener(listener EventListener) HTTPOption {
	return func(cfg *httpServerConfig) {
		cfg.listeners = append(cfg.listeners, listener)
	}
}
