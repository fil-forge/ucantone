package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
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
// fragment is refused too. So is one whose host is an IP address or is not a
// well-formed host name: the spec requires a domain name.
//
// A path character that a DID identifier cannot carry is percent-encoded, so
// https://example.com/~alice is did:web:example.com:%7Ealice.
//
// u is the URL the DID identifies, which is the one its document is served
// under. The URL of the document itself, ending in did.json, is refused.
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
	if _, err := netip.ParseAddr(host); err == nil {
		return did.Undef, fmt.Errorf("URL %q must name a host, not an IP address", u.String())
	}
	if err := checkHostName(host); err != nil {
		return did.Undef, fmt.Errorf("URL %q does not name a host: %w", u.String(), err)
	}

	id := host
	if port := u.Port(); port != "" && !isDefaultPort(u.Scheme, port) {
		id += "%3A" + port
	}
	// One slash at each end of the path is not a segment. Any more are empty
	// segments, which a DID cannot carry.
	path := strings.TrimSuffix(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	if path == "" && len(u.EscapedPath()) > 1 {
		return did.Undef, fmt.Errorf("URL %q has an empty path segment", u.String())
	}
	if path != "" {
		for _, segment := range strings.Split(path, "/") {
			if segment == "" {
				return did.Undef, fmt.Errorf("URL %q has an empty path segment", u.String())
			}
			id += ":" + escapeSegment(segment)
		}
		if strings.HasSuffix(id, ":did.json") {
			return did.Undef, fmt.Errorf("URL %q is the URL of a DID document: give the URL the DID identifies, which is the one did.json is served under", u.String())
		}
	}
	return Parse(did.Prefix + Method + ":" + id)
}

// escapeSegment percent-encodes the characters of an escaped URL path segment
// that a DID identifier cannot carry. The escapes the segment already has are
// kept as they are.
func escapeSegment(segment string) string {
	var b strings.Builder
	for i := 0; i < len(segment); i++ {
		if c := segment[i]; isIDChar(c) || c == '%' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// isIDChar reports whether c may appear unescaped in a DID identifier.
// https://www.w3.org/TR/did-core/#did-syntax
func isIDChar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '-' || c == '_'
}

// checkHostName reports why host is not a host name. A host name is labels
// separated by dots, 253 characters at most. A label is 1 to 63 letters,
// digits and hyphens, and does not start or end with a hyphen. A name in
// another script has to be in its ASCII form.
// https://www.rfc-editor.org/rfc/rfc1123#section-2
func checkHostName(host string) error {
	if len(host) > 253 {
		return fmt.Errorf("it is longer than 253 characters")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return fmt.Errorf("it has an empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q is longer than 63 characters", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("label %q starts or ends with a hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			if c := label[i]; !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return fmt.Errorf("label %q has a character other than a letter, a digit or a hyphen", label)
			}
		}
	}
	return nil
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "https" && port == "443") || (scheme == "http" && port == "80")
}

// Parse parses a did:web DID string, verifying the method is "web" and the
// identifier is a host, optionally followed by a percent-encoded colon and a
// port, then by any number of colon-separated path segments. The host has to
// be a host name, with labels of letters, digits and hyphens: the did:web spec
// does not allow an IP address. The string also
// has to be a DID that [did.Parse] accepts.
func Parse(str string) (did.DID, error) {
	d, err := did.Parse(str)
	if err != nil {
		return did.Undef, err
	}
	if err := did.ValidateMethod(d, Method); err != nil {
		return did.Undef, err
	}

	// did.Parse has checked the characters and escapes of the identifier, and
	// that it neither is empty nor ends with a colon.
	segments := strings.Split(d.Identifier(), ":")
	for i, segment := range segments {
		if segment == "" {
			if i == 0 {
				return did.Undef, fmt.Errorf("identifier has no host")
			}
			return did.Undef, fmt.Errorf("identifier has an empty path segment")
		}
	}

	// The host is the one segment where an escape has meaning: the colon
	// before a port.
	hostport, _ := url.PathUnescape(segments[0])
	host, port, hasPort := strings.Cut(hostport, ":")
	if host == "" {
		return did.Undef, fmt.Errorf("identifier has no host")
	}
	if err := checkHostName(host); err != nil {
		return did.Undef, fmt.Errorf("identifier host %q is not a host name: %w", host, err)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return did.Undef, fmt.Errorf("identifier host %q is an IP address, not a host name", host)
	}
	if hasPort {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return did.Undef, fmt.Errorf("identifier port %q is not a port number", port)
		}
	}
	return d, nil
}

// Location returns the https URL a did:web names: the inverse of [New].
//
//	did:web:example.com            https://example.com
//	did:web:example.com%3A3000     https://example.com:3000
//	did:web:example.com:user:alice https://example.com/user/alice
//
// The DID does not record a scheme. A caller on a stack that serves over HTTP
// sets the Scheme of the returned URL to "http". Percent-escapes in the path
// are carried into the URL as the DID has them.
//
// It fails for a DID that [Parse] refuses.
func Location(d did.DID) (url.URL, error) {
	if _, err := Parse(d.String()); err != nil {
		return url.URL{}, err
	}

	segments := strings.Split(d.Identifier(), ":")
	// Parse has checked the escapes.
	host, _ := url.PathUnescape(segments[0])
	u := url.URL{Scheme: "https", Host: host}
	if len(segments) > 1 {
		escaped := "/" + strings.Join(segments[1:], "/")
		path, _ := url.PathUnescape(escaped)
		u.Path = path
		if path != escaped {
			u.RawPath = escaped
		}
	}
	return u, nil
}

var _ did.Resolver = (*Resolver)(nil)

// Resolver resolves a did:web DID to a DID Document by fetching the document
// over HTTPS (or HTTP if configured), according to the did:web method spec.
// HTTP redirects are not followed unless [WithFollowRedirects] is set. A DID
// that [Parse] refuses, such as one whose host is an IP address, is not
// resolved and no request is made for it.
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

	url, err := documentURL(d, r.cfg.insecure)
	if err != nil {
		return did.Document{}, err
	}

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

// documentURL is where the DID document of d is fetched from: did.json under
// the DID's location, or the well-known path when the DID has no path.
func documentURL(d did.DID, insecure bool) (url.URL, error) {
	u, err := Location(d)
	if err != nil {
		return url.URL{}, err
	}
	if insecure {
		u.Scheme = "http"
	}
	if u.Path == "" {
		u.Path = WellKnownDIDPath
		return u, nil
	}
	u.Path += "/did.json"
	if u.RawPath != "" {
		u.RawPath += "/did.json"
	}
	return u, nil
}
