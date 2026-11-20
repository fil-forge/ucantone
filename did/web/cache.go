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
	// cacheControl is the Cache-Control response header the document arrived
	// with. It goes on applying when a 304 comes without one.
	cacheControl []string
	// expires is when the document stops being served without asking the
	// origin.
	expires time.Time
	// version identifies this write of the entry. The cache sets it.
	version uint64
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
	mu sync.Mutex
	// writes counts the entries written, to give each a version.
	writes uint64
	size   int
	order  *list.List // of entry, most recently used first
	items  map[string]*list.Element
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

// put stores e if the entry for its key is still the version the caller saw
// when it read the cache: zero for no entry. It does nothing otherwise, since
// another resolution has written the key in the meantime, and what this one
// holds may be older.
func (c *cache) put(e entry, seen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[e.key]
	if (ok && el.Value.(entry).version != seen) || (!ok && seen != 0) {
		return
	}
	c.writes++
	e.version = c.writes
	if ok {
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

// freshness works out whether a document may be kept, and for how long it may
// be served without asking the origin again, from the Cache-Control header of
// its response and the age the response had when it arrived (see
// [responseAge]).
//
// A Cache-Control max-age sets the lifetime, capped at maxTTL; without one the
// lifetime is defaultTTL. The age is subtracted. no-cache gives a lifetime
// of zero (keep, but revalidate before every use) and no-store forbids
// keeping the document. Each wins over max-age, and no-store over no-cache,
// wherever it appears.
func freshness(cacheControl []string, age, defaultTTL, maxTTL time.Duration) (ttl time.Duration, store bool) {
	ttl = defaultTTL
	noCache := false
	for _, value := range cacheControl {
		for directive := range strings.SplitSeq(value, ",") {
			name, arg, _ := strings.Cut(strings.TrimSpace(directive), "=")
			switch strings.ToLower(name) {
			case "no-store":
				return 0, false
			case "no-cache":
				noCache = true
			case "max-age":
				ttl = min(seconds(arg, maxTTL), maxTTL)
			}
		}
	}
	if noCache {
		return 0, true
	}
	return max(ttl-age, 0), true
}

// maxAge is the largest response age reported. Anything older is as stale as
// it needs to be.
const maxAge = 365 * 24 * time.Hour

// responseAge is how old a response already was when it arrived at now: the
// larger of its Age header, set by intermediaries that served it from their
// own cache, and the time since its Date header, which covers intermediaries
// that set no Age. A Date in the future, or one that does not parse, counts
// for nothing.
func responseAge(h http.Header, now time.Time) time.Duration {
	age := seconds(h.Get("Age"), maxAge)
	if date, err := http.ParseTime(h.Get("Date")); err == nil {
		age = max(age, min(now.Sub(date), maxAge))
	}
	return age
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
