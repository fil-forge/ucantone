package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fil-forge/ucantone/did"
)

const Method = "web"

const WellKnownDIDPath = "/.well-known/did.json"

var _ did.Resolver = (*Resolver)(nil)

// Resolver resolves a did:web DID to a DID Document by fetching the document
// over HTTPS (or HTTP if configured), according to the did:web method spec.
// HTTP redirects are not followed unless [WithFollowRedirects] is set.
// https://w3c-ccg.github.io/did-method-web/#read-resolve
//
// Resolved documents are cached in memory. A document is served from the
// cache for the max-age its response's Cache-Control header gives, or for the
// [WithCacheTTL] duration when the response has none. After that the resolver
// asks the origin again, and when the response carried an ETag or
// Last-Modified header it makes the request conditional, so an unchanged
// document costs a 304 with no body. Failed resolutions are not cached, and a
// stale document is never returned when the origin cannot be reached.
//
// A returned document shares its verification methods and other contents with
// the cache, as it does with the other resolutions of the same DID. Treat it
// as read-only.
type Resolver struct {
	cfg   config
	cache *cache // nil when caching is disabled
}

func NewResolver(options ...Option) (*Resolver, error) {
	cfg := &config{
		// default timeout of 10 seconds
		timeout:     10 * time.Second,
		insecure:    false,
		cacheTTL:    DefaultCacheTTL,
		maxCacheTTL: DefaultMaxCacheTTL,
		cacheSize:   DefaultCacheSize,
		now:         time.Now,
	}
	for _, opt := range options {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	r := &Resolver{cfg: *cfg}
	if cfg.cacheTTL > 0 {
		r.cache = newCache(cfg.cacheSize)
	}
	return r, nil
}

func (r *Resolver) Resolve(ctx context.Context, d did.DID) (did.Document, error) {
	if err := did.ValidateMethod(d, Method); err != nil {
		return did.Document{}, err
	}

	if r.cfg.globs != nil {
		match := false
		for _, g := range r.cfg.globs {
			if match = g.Match(d.Identifier()); match {
				break
			}
		}
		if !match {
			return did.Document{}, fmt.Errorf("resolution of %s via HTTP not permitted", d)
		}
	}

	// The cached document, when it is stale and can be revalidated.
	var stale *entry
	// The version of the cache entry seen, if there is one. The response only
	// updates the cache if the entry is still that version when it arrives.
	var seen uint64
	if r.cache != nil {
		if e, ok := r.cache.get(d.String()); ok {
			if r.cfg.now().Before(e.expires) {
				return e.doc, nil
			}
			seen = e.version
			if e.revalidatable() {
				stale = &e
			}
		}
	}

	url := documentURL(d, r.cfg.insecure)

	httpClient := &http.Client{
		Timeout:   r.cfg.timeout,
		Transport: r.cfg.transport,
	}
	if !r.cfg.followRedirects {
		httpClient.CheckRedirect = refuseRedirect
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return did.Document{}, fmt.Errorf("creating HTTP request: %w", err)
	}
	if stale != nil {
		if stale.etag != "" {
			req.Header.Set("If-None-Match", stale.etag)
		}
		if stale.lastModified != "" {
			req.Header.Set("If-Modified-Since", stale.lastModified)
		}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return did.Document{}, fmt.Errorf("performing HTTP request: %w", err)
	}
	defer resp.Body.Close()

	fresh := entry{key: d.String()}
	switch {
	case resp.StatusCode == http.StatusOK:
		if err := json.NewDecoder(resp.Body).Decode(&fresh.doc); err != nil {
			return did.Document{}, fmt.Errorf("parsing DID document JSON: %w", err)
		}
		fresh.etag = resp.Header.Get("ETag")
		fresh.lastModified = resp.Header.Get("Last-Modified")
		fresh.cacheControl = resp.Header.Values("Cache-Control")
	case resp.StatusCode == http.StatusNotModified && stale != nil:
		// The cached document is still current. A 304 may carry new
		// validators or a new Cache-Control; what came with the document
		// stands otherwise.
		fresh = *stale
		if cacheControl := resp.Header.Values("Cache-Control"); len(cacheControl) > 0 {
			fresh.cacheControl = cacheControl
		}
		if etag := resp.Header.Get("ETag"); etag != "" {
			fresh.etag = etag
		}
		if lastModified := resp.Header.Get("Last-Modified"); lastModified != "" {
			fresh.lastModified = lastModified
		}
	default:
		return did.Document{}, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	if r.cache != nil {
		ttl, store := freshness(fresh.cacheControl, resp.Header.Get("Age"), r.cfg.cacheTTL, r.cfg.maxCacheTTL)
		// A document with no lifetime is only worth keeping when it can be
		// revalidated.
		if store && (ttl > 0 || fresh.revalidatable()) {
			fresh.expires = r.cfg.now().Add(ttl)
			r.cache.put(fresh, seen)
		} else {
			r.cache.remove(fresh.key)
		}
	}

	return fresh.doc, nil
}

// refuseRedirect is an [http.Client] redirect policy that fails the request
// instead of following the redirect.
func refuseRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("redirect to %q not followed", req.URL)
}

func documentURL(d did.DID, insecure bool) url.URL {
	scheme := "https"
	if insecure {
		scheme = "http"
	}

	segments := strings.Split(d.Identifier(), ":")
	host := segments[0]
	// Unescape percent-encoded colons in the host, to support port numbers.
	host = strings.ReplaceAll(host, "%3A", ":")
	path := ""
	if len(segments) > 1 {
		path = "/" + strings.Join(segments[1:], "/") + "/did.json"
	} else {
		path = WellKnownDIDPath
	}
	return url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   path,
	}
}
