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

// Cache is the subset of github.com/patrickmn/go-cache's API used by the
// resolver to cache DID documents. A *cache.Cache satisfies this interface.
type Cache interface {
	Get(k string) (interface{}, bool)
	Set(k string, x interface{}, d time.Duration)
}

type config struct {
	timeout         time.Duration
	transport       http.RoundTripper
	cache           Cache
	cacheExpiration time.Duration
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

// WithCache configures the resolver to cache resolved DID documents. When set,
// the resolver stores the document alongside the ETag returned by the directory
// and issues conditional requests (If-None-Match) on subsequent resolutions,
// returning the cached document when the directory responds 304 Not Modified.
func WithCache(cache Cache) Option {
	return func(c *config) {
		c.cache = cache
	}
}

// WithCacheExpiration sets the expiration duration passed to the cache's Set
// when storing a resolved document. It only has an effect alongside WithCache.
// The zero value is go-cache's DefaultExpiration, meaning the cache's own
// configured default is used; pass a negative duration for go-cache's
// NoExpiration.
func WithCacheExpiration(expiration time.Duration) Option {
	return func(c *config) {
		c.cacheExpiration = expiration
	}
}

// cachedDocument is the value stored in the cache: a resolved document and the
// ETag it was served with, keyed by the DID string.
type cachedDocument struct {
	etag string
	doc  did.Document
}

var _ did.Resolver = (*Resolver)(nil)

// Resolver resolves a did:plc DID to a DID Document by fetching the document
// from the configured directory.
type Resolver struct {
	endpoint        url.URL
	client          *http.Client
	cache           Cache
	cacheExpiration time.Duration
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
	return &Resolver{endpoint: endpoint, client: &c, cache: cfg.cache, cacheExpiration: cfg.cacheExpiration}, nil
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

	// If we have a cached document with an ETag, revalidate it conditionally so
	// the directory can respond 304 Not Modified instead of resending the body.
	var cached cachedDocument
	var haveCached bool
	if r.cache != nil {
		if v, found := r.cache.Get(d.String()); found {
			if entry, ok := v.(cachedDocument); ok {
				cached = entry
				haveCached = true
				if entry.etag != "" {
					req.Header.Set("If-None-Match", entry.etag)
				}
			}
		}
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return did.Document{}, fmt.Errorf("performing HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified && haveCached {
		return cached.doc, nil
	}

	if resp.StatusCode != http.StatusOK {
		return did.Document{}, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var doc did.Document
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return did.Document{}, fmt.Errorf("parsing DID document JSON: %w", err)
	}

	// Cache the document keyed by DID, along with its ETag for future
	// revalidation. Only cache when an ETag is present so every subsequent hit
	// revalidates rather than risk serving a stale document. The expiration is
	// configurable via WithCacheExpiration; its zero value is go-cache's
	// DefaultExpiration, letting the caller's cache config govern TTL.
	if r.cache != nil {
		if etag := resp.Header.Get("ETag"); etag != "" {
			r.cache.Set(d.String(), cachedDocument{etag: etag, doc: doc}, r.cacheExpiration)
		}
	}

	return doc, nil
}
