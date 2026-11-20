package web

import (
	"container/list"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fil-forge/ucantone/did"
)

// entry is a resolved DID document with what is needed to serve it from
// memory and to revalidate it with the origin once it is stale.
type entry struct {
	key string
	doc did.Document
	// etag is the ETag response header the document arrived with, sent back
	// as If-None-Match when revalidating.
	etag string
	// lastModified is the Last-Modified response header the document arrived
	// with, sent back as If-Modified-Since when revalidating.
	lastModified string
	// expires is when the document stops being served without asking the
	// origin.
	expires time.Time
}

// revalidatable reports whether the origin gave a validator for the document,
// so a conditional request can be made for it.
func (e entry) revalidatable() bool {
	return e.etag != "" || e.lastModified != ""
}

// cache holds the most recently used documents, up to a fixed number. Stale
// documents stay in it so they can be revalidated; they leave when newer
// documents push them out.
type cache struct {
	mu    sync.Mutex
	size  int
	order *list.List // of entry, most recently used first
	items map[string]*list.Element
}

func newCache(size int) *cache {
	return &cache{size: size, order: list.New(), items: map[string]*list.Element{}}
}

func (c *cache) get(key string) (entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return entry{}, false
	}
	c.order.MoveToFront(el)
	return el.Value.(entry), true
}

func (c *cache) put(e entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[e.key]; ok {
		el.Value = e
		c.order.MoveToFront(el)
		return
	}
	c.items[e.key] = c.order.PushFront(e)
	for c.order.Len() > c.size {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(entry).key)
	}
}

func (c *cache) remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}

// freshness works out from the response headers whether a document may be
// kept, and for how long it may be served without asking the origin again.
//
// A Cache-Control max-age sets the lifetime, capped at maxTTL; without one the
// lifetime is defaultTTL. The Age header, set by intermediaries that served
// the response from their own cache, is subtracted. no-cache gives a lifetime
// of zero (keep, but revalidate before every use) and no-store forbids
// keeping the document.
func freshness(h http.Header, defaultTTL, maxTTL time.Duration) (ttl time.Duration, store bool) {
	ttl = defaultTTL
	for _, value := range h.Values("Cache-Control") {
		for directive := range strings.SplitSeq(value, ",") {
			name, arg, _ := strings.Cut(strings.TrimSpace(directive), "=")
			switch strings.ToLower(name) {
			case "no-store":
				return 0, false
			case "no-cache":
				return 0, true
			case "max-age":
				ttl = min(seconds(arg, maxTTL), maxTTL)
			}
		}
	}
	ttl -= seconds(h.Get("Age"), ttl)
	return max(ttl, 0), true
}

// seconds parses a non-negative whole number of seconds, as used by max-age
// and Age. Values over limit come back as limit, and anything unparsable as
// zero.
func seconds(s string, limit time.Duration) time.Duration {
	n, err := strconv.ParseUint(strings.Trim(strings.TrimSpace(s), `"`), 10, 64)
	if err != nil {
		if numErr, ok := err.(*strconv.NumError); ok && numErr.Err == strconv.ErrRange {
			return limit
		}
		return 0
	}
	if n > uint64(limit/time.Second) {
		return limit
	}
	return time.Duration(n) * time.Second
}
