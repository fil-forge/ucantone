package utilresolvers

import (
	"context"
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/patrickmn/go-cache"
)

type Cached struct {
	wrapped did.Resolver
	cache   *cache.Cache
}

var _ did.Resolver = (*Cached)(nil)

func NewCached(wrapped did.Resolver, ttl time.Duration) *Cached {
	// items remain in the cache for `ttl`, expired items are purged every hour.
	return &Cached{wrapped: wrapped, cache: cache.New(ttl, time.Hour)}
}

func (c *Cached) Resolve(ctx context.Context, input did.DID) (did.Document, error) {
	if out, found := c.cache.Get(input.String()); found {
		return out.(did.Document), nil
	}
	out, err := c.wrapped.Resolve(ctx, input)
	if err != nil {
		return did.Document{}, err
	}
	c.cache.Set(input.String(), out, cache.DefaultExpiration)

	return out, nil
}
