package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fil-forge/ucantone/did"
)

const Method = "web"

const WellKnownDIDPath = "/.well-known/did.json"

// New returns the did:web that identifies the resource at the https URL u,
// according to the did:web method spec. The host becomes the identifier, in
// lower case. A port follows it with its colon percent-encoded, unless it is
// the default for the scheme. Each path segment follows, separated by colons:
//
//	https://example.com            did:web:example.com
//	https://example.com:3000       did:web:example.com%3A3000
//	https://example.com/user/alice did:web:example.com:user:alice
//
// The scheme is not part of the DID, but a did:web document is fetched over
// HTTPS, so any other scheme is refused. A URL with user info, a query or a
// fragment is refused too, as is one whose host is an IPv6 address.
//
// https://w3c-ccg.github.io/did-method-web/#create-register
func New(u url.URL) (did.DID, error) {
	if u.Scheme != "https" {
		return did.Undef, fmt.Errorf("URL %q must be an https URL", u.Redacted())
	}
	return newDID(u)
}

// NewInsecure is [New] for hosts whose documents are resolved with
// [WithInsecure]: it accepts an http URL as well as an https one. Use it only
// where every resolver of the DID fetches documents over HTTP, such as a
// development stack.
func NewInsecure(u url.URL) (did.DID, error) {
	if u.Scheme != "https" && u.Scheme != "http" {
		return did.Undef, fmt.Errorf("URL %q must be an http or https URL", u.Redacted())
	}
	return newDID(u)
}

// newDID builds the did:web of a URL whose scheme has been checked.
func newDID(u url.URL) (did.DID, error) {
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return did.Undef, fmt.Errorf("URL %q must have no user info, query or fragment", u.Redacted())
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return did.Undef, fmt.Errorf("URL %q has no host", u.String())
	}
	if strings.Contains(host, ":") {
		return did.Undef, fmt.Errorf("URL %q must name a host, not an IPv6 address", u.String())
	}

	id := host
	if port := u.Port(); port != "" && !isDefaultPort(u.Scheme, port) {
		id += "%3A" + port
	}
	if path := strings.Trim(u.EscapedPath(), "/"); path != "" {
		for _, segment := range strings.Split(path, "/") {
			if segment == "" {
				return did.Undef, fmt.Errorf("URL %q has an empty path segment", u.String())
			}
			// A colon separates the segments of the identifier.
			id += ":" + strings.ReplaceAll(segment, ":", "%3A")
		}
	}
	return Parse(did.Prefix + Method + ":" + id)
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "https" && port == "443") || (scheme == "http" && port == "80")
}

// Parse parses a did:web DID string, verifying the method is "web" and the
// identifier is a host, optionally followed by a percent-encoded colon and a
// port, then by any number of colon-separated path segments.
func Parse(str string) (did.DID, error) {
	d, err := did.Parse(str)
	if err != nil {
		return did.Undef, err
	}
	if err := did.ValidateMethod(d, Method); err != nil {
		return did.Undef, err
	}

	segments := strings.Split(d.Identifier(), ":")
	for i, segment := range segments {
		if segment == "" {
			if i == 0 {
				return did.Undef, fmt.Errorf("identifier has no host")
			}
			return did.Undef, fmt.Errorf("identifier has an empty path segment")
		}
		if strings.ContainsAny(segment, "/?#") {
			return did.Undef, fmt.Errorf("identifier segment %q contains a character that must be percent-encoded", segment)
		}
		if _, err := url.PathUnescape(segment); err != nil {
			return did.Undef, fmt.Errorf("identifier segment %q is not percent-encoded correctly: %w", segment, err)
		}
	}

	// The host is the one segment where an escape has meaning: the colon
	// before a port.
	hostport, _ := url.PathUnescape(segments[0])
	host, port, hasPort := strings.Cut(hostport, ":")
	if host == "" {
		return did.Undef, fmt.Errorf("identifier has no host")
	}
	if strings.ContainsAny(host, "@[] ") {
		return did.Undef, fmt.Errorf("identifier host %q is not a host name", host)
	}
	if hasPort {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return did.Undef, fmt.Errorf("identifier port %q is not a port number", port)
		}
	}
	return d, nil
}

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
	if r.cache != nil {
		if e, ok := r.cache.get(d.String()); ok {
			if r.cfg.now().Before(e.expires) {
				return e.doc, nil
			}
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
	notModified := false
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
		notModified = true
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
		now := r.cfg.now()
		ttl, store := freshness(fresh.cacheControl, responseAge(resp.Header, now), r.cfg.cacheTTL, r.cfg.maxCacheTTL)
		// A document with no lifetime is only worth keeping when it can be
		// revalidated.
		switch {
		case !store || (ttl == 0 && !fresh.revalidatable()):
			r.cache.remove(fresh.key)
		case notModified:
			// Another resolution may have fetched a newer document while
			// this one was being revalidated. A 304 never replaces it.
			fresh.expires = now.Add(ttl)
			r.cache.renew(fresh, stale.version)
		default:
			// A fetched document always goes in, so one that arrives after
			// a 304 for its predecessor replaces what the 304 renewed.
			fresh.expires = now.Add(ttl)
			r.cache.put(fresh)
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
	// Unescape the percent-encoded colon in the host, to support port numbers.
	// Hex digits in an escape are equivalent in either case.
	host = strings.NewReplacer("%3A", ":", "%3a", ":").Replace(host)
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
