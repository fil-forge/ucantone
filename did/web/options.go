package web

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gobwas/glob"
)

const (
	// DefaultCacheTTL is how long a resolved document is served from the cache
	// when its response has no Cache-Control max-age.
	DefaultCacheTTL = 5 * time.Minute
	// DefaultMaxCacheTTL is the longest a document is served from the cache
	// without asking the origin again, whatever max-age its response gave.
	DefaultMaxCacheTTL = 24 * time.Hour
	// DefaultCacheSize is the number of documents the cache holds.
	DefaultCacheSize = 1024
)

type config struct {
	timeout   time.Duration
	insecure  bool
	globs     map[string]*glob.Pattern
	transport http.RoundTripper
	// followRedirects makes the resolver follow HTTP redirects.
	followRedirects bool
	// cacheTTL is the cache lifetime of a document whose response has no
	// Cache-Control max-age. Zero disables the cache.
	cacheTTL time.Duration
	// maxCacheTTL caps the lifetime a response's max-age can ask for.
	maxCacheTTL time.Duration
	// cacheSize is the number of documents the cache holds.
	cacheSize int
	// now is the clock the cache reads.
	now func() time.Time
}

type Option func(*config) error

func WithTimeout(timeout time.Duration) Option {
	return func(c *config) error {
		if timeout == 0 {
			return fmt.Errorf("timeout cannot be zero")
		}
		c.timeout = timeout
		return nil
	}
}

func WithInsecure(insecure bool) Option {
	return func(c *config) error {
		c.insecure = insecure
		return nil
	}
}

// WithPatterns restricts resolution to DIDs with identifiers which match the
// provided glob patterns. Patterns are matched against the DID identifier only,
// not the `did:web:` prefix.
func WithPatterns(patterns ...string) Option {
	return func(c *config) error {
		for _, p := range patterns {
			g, err := glob.Compile(p)
			if err != nil {
				return fmt.Errorf("compiling pattern %q: %w", p, err)
			}
			if c.globs == nil {
				c.globs = map[string]*glob.Pattern{}
			}
			c.globs[p] = g
		}
		return nil
	}
}

func WithTransport(transport http.RoundTripper) Option {
	return func(c *config) error {
		if transport == nil {
			return fmt.Errorf("transport cannot be nil")
		}
		c.transport = transport
		return nil
	}
}

// WithFollowRedirects sets whether the resolver follows HTTP redirects when
// fetching a DID document. It does not by default: a redirect response fails
// the resolution, so the document always comes from the host the DID names.
//
// When enabled, the standard [http.Client] policy applies (up to 10
// redirects). A redirect target is not checked against the patterns given to
// [WithPatterns] and may use a different host or scheme than the DID.
func WithFollowRedirects(follow bool) Option {
	return func(c *config) error {
		c.followRedirects = follow
		return nil
	}
}

// WithCacheTTL sets how long a resolved document is served from the cache
// when its response has no Cache-Control max-age. The default is
// [DefaultCacheTTL]. Zero disables the cache: every resolution fetches the
// document.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *config) error {
		if ttl < 0 {
			return fmt.Errorf("cache TTL cannot be negative")
		}
		c.cacheTTL = ttl
		return nil
	}
}

// WithMaxCacheTTL caps how long a document is served from the cache when its
// response's Cache-Control max-age asks for longer. The default is
// [DefaultMaxCacheTTL]. The cap bounds how long a key removed from a document
// can go on being trusted because the origin once sent a long max-age. It
// does not apply to the [WithCacheTTL] duration.
func WithMaxCacheTTL(ttl time.Duration) Option {
	return func(c *config) error {
		if ttl <= 0 {
			return fmt.Errorf("max cache TTL must be positive")
		}
		c.maxCacheTTL = ttl
		return nil
	}
}

// WithCacheSize sets the number of documents the cache holds. The default is
// [DefaultCacheSize]. When the cache is full the least recently used document
// is dropped.
func WithCacheSize(size int) Option {
	return func(c *config) error {
		if size <= 0 {
			return fmt.Errorf("cache size must be positive")
		}
		c.cacheSize = size
		return nil
	}
}
