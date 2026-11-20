package web

import "time"

// WithClock sets the clock the cache reads, so tests can move time.
func WithClock(now func() time.Time) Option {
	return func(c *config) error {
		c.now = now
		return nil
	}
}
