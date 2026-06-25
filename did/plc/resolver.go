//go:build !codegen

package plc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/fil-forge/ucantone/did"
)

type config struct {
	timeout   time.Duration
	transport http.RoundTripper
}

type Option func(*config)

func WithTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.timeout = timeout
	}
}

func WithTransport(transport http.RoundTripper) Option {
	return func(c *config) {
		c.transport = transport
	}
}

var _ did.Resolver = (*Resolver)(nil)

// Resolver resolves a did:plc DID to a DID Document by fetching the document
// from the configured directory.
type Resolver struct {
	endpoint url.URL
	client   *http.Client
}

func NewResolver(endpoint url.URL, options ...Option) (*Resolver, error) {
	cfg := config{}
	for _, opt := range options {
		opt(&cfg)
	}
	if cfg.timeout <= 0 {
		// default timeout of 10 seconds
		cfg.timeout = 10 * time.Second
	}
	c := http.Client{
		Timeout:   cfg.timeout,
		Transport: cfg.transport,
	}
	return &Resolver{endpoint: endpoint, client: &c}, nil
}

func (r *Resolver) Resolve(ctx context.Context, d did.DID) (did.Document, error) {
	if err := did.ValidateMethod(d, Method); err != nil {
		return did.Document{}, err
	}

	url := r.endpoint.JoinPath(d.String())
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return did.Document{}, fmt.Errorf("creating HTTP request: %w", err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return did.Document{}, fmt.Errorf("performing HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return did.Document{}, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var doc did.Document
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return did.Document{}, fmt.Errorf("parsing DID document JSON: %w", err)
	}

	return doc, nil
}
