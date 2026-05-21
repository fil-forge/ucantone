package client

import (
	"net/http"

	"github.com/fil-forge/ucantone/transport"
)

type httpClientConfig struct {
	client    *http.Client
	codec     transport.OutboundCodec[*http.Request, *http.Response]
	listeners []EventListener
}

type HTTPOption func(*httpClientConfig)

func WithHTTPClient(client *http.Client) HTTPOption {
	return func(cfg *httpClientConfig) {
		cfg.client = client
	}
}

func WithHTTPCodec(codec transport.OutboundCodec[*http.Request, *http.Response]) HTTPOption {
	return func(cfg *httpClientConfig) {
		cfg.codec = codec
	}
}

// WithEventListener registers an [EventListener] to observe the client's
// requests and responses as they are encoded and decoded.
func WithEventListener(listener EventListener) HTTPOption {
	return func(cfg *httpClientConfig) {
		cfg.listeners = append(cfg.listeners, listener)
	}
}
