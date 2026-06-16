package web

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gobwas/glob"
)

type config struct {
	timeout   time.Duration
	insecure  bool
	globs     map[string]glob.Glob
	transport http.RoundTripper
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
				c.globs = map[string]glob.Glob{}
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
