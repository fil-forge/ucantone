package web_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/web"
	"github.com/stretchr/testify/require"
)

// clock is a manually advanced clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock {
	return &clock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// origin is a did:web host serving one document per DID. It records the
// requests it receives and answers conditional requests with 304.
type origin struct {
	mu sync.Mutex
	// header is added to every response.
	header http.Header
	// etag and lastModified are the validators of the current document. An
	// empty value is not sent.
	etag         string
	lastModified string
	// alsoKnownAs distinguishes one version of the document from the next.
	alsoKnownAs string
	// err, when set, fails every request.
	err error
	// status, when set, replaces the response with a bodiless one.
	status   int
	requests []*http.Request
}

func (o *origin) RoundTrip(r *http.Request) (*http.Response, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.requests = append(o.requests, r)
	if o.err != nil {
		return nil, o.err
	}

	header := o.header.Clone()
	if header == nil {
		header = http.Header{}
	}
	if o.etag != "" {
		header.Set("ETag", o.etag)
	}
	if o.lastModified != "" {
		header.Set("Last-Modified", o.lastModified)
	}
	respond := func(status int, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body))}, nil
	}

	if o.status != 0 {
		return respond(o.status, nil)
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		if inm == o.etag {
			return respond(http.StatusNotModified, nil)
		}
	} else if ims := r.Header.Get("If-Modified-Since"); ims != "" && ims == o.lastModified {
		return respond(http.StatusNotModified, nil)
	}

	id := "did:web:" + r.URL.Host
	doc := did.NewDocument(did.MustParse(id))
	if o.alsoKnownAs != "" {
		u, err := did.ParseURL(o.alsoKnownAs)
		if err != nil {
			return nil, err
		}
		doc.AlsoKnownAs = []did.URL{u}
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return respond(http.StatusOK, body)
}

func (o *origin) set(fn func(o *origin)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fn(o)
}

func (o *origin) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.requests)
}

func (o *origin) last() *http.Request {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.requests[len(o.requests)-1]
}

func TestResolverCache(t *testing.T) {
	example := did.MustParse("did:web:example.com")

	setup := func(t *testing.T, o *origin, options ...web.Option) (*web.Resolver, *clock) {
		t.Helper()
		c := newClock()
		options = append([]web.Option{web.WithTransport(o), web.WithClock(c.Now)}, options...)
		resolver, err := web.NewResolver(options...)
		require.NoError(t, err)
		return resolver, c
	}

	resolve := func(t *testing.T, resolver *web.Resolver, d did.DID) did.Document {
		t.Helper()
		doc, err := resolver.Resolve(t.Context(), d)
		require.NoError(t, err)
		require.Equal(t, d, doc.ID)
		return doc
	}

	t.Run("serves from the cache for the default TTL", func(t *testing.T) {
		o := &origin{}
		resolver, c := setup(t, o)

		resolve(t, resolver, example)
		c.Advance(web.DefaultCacheTTL - time.Second)
		resolve(t, resolver, example)
		require.Equal(t, 1, o.count())

		c.Advance(time.Second)
		resolve(t, resolver, example)
		require.Equal(t, 2, o.count())
	})

	t.Run("serves from the cache for the configured TTL", func(t *testing.T) {
		o := &origin{}
		resolver, c := setup(t, o, web.WithCacheTTL(time.Minute))

		resolve(t, resolver, example)
		c.Advance(59 * time.Second)
		resolve(t, resolver, example)
		require.Equal(t, 1, o.count())

		c.Advance(time.Second)
		resolve(t, resolver, example)
		require.Equal(t, 2, o.count())
	})

	t.Run("does not cache when the TTL is zero", func(t *testing.T) {
		o := &origin{etag: `"v1"`, header: http.Header{"Cache-Control": {"max-age=60"}}}
		resolver, _ := setup(t, o, web.WithCacheTTL(0))

		resolve(t, resolver, example)
		resolve(t, resolver, example)
		require.Equal(t, 2, o.count())
		require.Empty(t, o.last().Header.Get("If-None-Match"))
	})

	t.Run("caches each DID separately", func(t *testing.T) {
		o := &origin{}
		resolver, _ := setup(t, o)
		other := did.MustParse("did:web:other.example")

		resolve(t, resolver, example)
		resolve(t, resolver, other)
		resolve(t, resolver, example)
		resolve(t, resolver, other)
		require.Equal(t, 2, o.count())
	})

	t.Run("does not cache failures", func(t *testing.T) {
		o := &origin{status: http.StatusNotFound}
		resolver, _ := setup(t, o)

		_, err := resolver.Resolve(t.Context(), example)
		require.ErrorContains(t, err, "unexpected status: 404")
		_, err = resolver.Resolve(t.Context(), example)
		require.ErrorContains(t, err, "unexpected status: 404")
		require.Equal(t, 2, o.count())
	})

	t.Run("drops the least recently used document when full", func(t *testing.T) {
		o := &origin{}
		resolver, _ := setup(t, o, web.WithCacheSize(2))
		a, b, c := did.MustParse("did:web:a.example"), did.MustParse("did:web:b.example"), did.MustParse("did:web:c.example")

		resolve(t, resolver, a)
		resolve(t, resolver, b)
		resolve(t, resolver, a) // b is now the least recently used
		resolve(t, resolver, c) // pushes b out
		require.Equal(t, 3, o.count())

		resolve(t, resolver, a)
		resolve(t, resolver, c)
		require.Equal(t, 3, o.count())
		resolve(t, resolver, b)
		require.Equal(t, 4, o.count())
	})

	t.Run("Cache-Control", func(t *testing.T) {
		tests := []struct {
			name   string
			header http.Header
			// fresh is how long the document is served without a request.
			// Zero means every resolution makes a request.
			fresh time.Duration
		}{
			{"max-age longer than the default", http.Header{"Cache-Control": {"max-age=3600"}}, time.Hour},
			{"max-age shorter than the default", http.Header{"Cache-Control": {"max-age=10"}}, 10 * time.Second},
			{"max-age among other directives", http.Header{"Cache-Control": {"public, Max-Age=10, must-revalidate"}}, 10 * time.Second},
			{"max-age in a second header line", http.Header{"Cache-Control": {"public", "max-age=10"}}, 10 * time.Second},
			{"quoted max-age", http.Header{"Cache-Control": {`max-age="10"`}}, 10 * time.Second},
			{"max-age of zero", http.Header{"Cache-Control": {"max-age=0"}}, 0},
			{"unparsable max-age", http.Header{"Cache-Control": {"max-age=soon"}}, 0},
			{"max-age over the cap", http.Header{"Cache-Control": {"max-age=31536000"}}, web.DefaultMaxCacheTTL},
			{"max-age too large for an integer", http.Header{"Cache-Control": {"max-age=99999999999999999999999"}}, web.DefaultMaxCacheTTL},
			{"s-maxage is for shared caches", http.Header{"Cache-Control": {"s-maxage=10"}}, web.DefaultCacheTTL},
			{"no-cache", http.Header{"Cache-Control": {"no-cache, max-age=3600"}}, 0},
			{"no-cache after max-age", http.Header{"Cache-Control": {"max-age=3600, no-cache"}}, 0},
			{"no-store", http.Header{"Cache-Control": {"no-store, max-age=3600"}}, 0},
			{"Age counts against max-age", http.Header{"Cache-Control": {"max-age=60"}, "Age": {"45"}}, 15 * time.Second},
			{"Age counts against the default", http.Header{"Age": {"60"}}, web.DefaultCacheTTL - time.Minute},
			{"Age beyond max-age", http.Header{"Cache-Control": {"max-age=60"}, "Age": {"90"}}, 0},
			// The clock starts at midnight on 1 January 2026.
			{"time since Date counts against max-age", http.Header{"Cache-Control": {"max-age=60"}, "Date": {"Wed, 31 Dec 2025 23:59:15 GMT"}}, 15 * time.Second},
			{"time since Date counts against the default", http.Header{"Date": {"Wed, 31 Dec 2025 23:59:00 GMT"}}, web.DefaultCacheTTL - time.Minute},
			{"Date older than max-age", http.Header{"Cache-Control": {"max-age=60"}, "Date": {"Wed, 31 Dec 2025 23:00:00 GMT"}}, 0},
			{"Date older than Age", http.Header{"Cache-Control": {"max-age=60"}, "Age": {"10"}, "Date": {"Wed, 31 Dec 2025 23:59:15 GMT"}}, 15 * time.Second},
			{"Age older than Date", http.Header{"Cache-Control": {"max-age=60"}, "Age": {"45"}, "Date": {"Wed, 31 Dec 2025 23:59:50 GMT"}}, 15 * time.Second},
			{"Date in the future", http.Header{"Cache-Control": {"max-age=60"}, "Date": {"Thu, 01 Jan 2026 00:10:00 GMT"}}, time.Minute},
			{"unparsable Date", http.Header{"Cache-Control": {"max-age=60"}, "Date": {"yesterday"}}, time.Minute},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				o := &origin{header: tt.header}
				resolver, c := setup(t, o)

				resolve(t, resolver, example)
				if tt.fresh > 0 {
					c.Advance(tt.fresh - time.Second)
					resolve(t, resolver, example)
					require.Equal(t, 1, o.count(), "served from the cache while fresh")
					c.Advance(time.Second)
				}
				resolve(t, resolver, example)
				require.Equal(t, 2, o.count(), "fetched once stale")
			})
		}
	})

	t.Run("honours a configured cap on max-age", func(t *testing.T) {
		o := &origin{header: http.Header{"Cache-Control": {"max-age=3600"}}}
		resolver, c := setup(t, o, web.WithMaxCacheTTL(time.Minute))

		resolve(t, resolver, example)
		c.Advance(59 * time.Second)
		resolve(t, resolver, example)
		require.Equal(t, 1, o.count())
		c.Advance(time.Second)
		resolve(t, resolver, example)
		require.Equal(t, 2, o.count())
	})

	t.Run("revalidation", func(t *testing.T) {
		const modified = "Thu, 01 Jan 2026 00:00:00 GMT"

		tests := []struct {
			name         string
			etag         string
			lastModified string
		}{
			{"with ETag", `"v1"`, ""},
			{"with weak ETag", `W/"v1"`, ""},
			{"with Last-Modified", "", modified},
			{"with both", `"v1"`, modified},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				o := &origin{etag: tt.etag, lastModified: tt.lastModified, alsoKnownAs: "did:example:one"}
				resolver, c := setup(t, o)

				first := resolve(t, resolver, example)
				require.Empty(t, o.last().Header.Get("If-None-Match"))
				require.Empty(t, o.last().Header.Get("If-Modified-Since"))

				// Unchanged at the origin: a conditional request, answered
				// with 304, returns the cached document and makes it fresh
				// again.
				c.Advance(web.DefaultCacheTTL)
				second := resolve(t, resolver, example)
				require.Equal(t, 2, o.count())
				require.Equal(t, tt.etag, o.last().Header.Get("If-None-Match"))
				require.Equal(t, tt.lastModified, o.last().Header.Get("If-Modified-Since"))
				require.Equal(t, first, second)

				c.Advance(web.DefaultCacheTTL - time.Second)
				resolve(t, resolver, example)
				require.Equal(t, 2, o.count())

				// Changed at the origin: the conditional request gets the new
				// document, and its validators replace the old ones.
				o.set(func(o *origin) {
					o.alsoKnownAs = "did:example:two"
					if o.etag != "" {
						o.etag = `"v2"`
					}
					if o.lastModified != "" {
						o.lastModified = "Fri, 02 Jan 2026 00:00:00 GMT"
					}
				})
				c.Advance(time.Second)
				third := resolve(t, resolver, example)
				require.Equal(t, 3, o.count())
				require.Equal(t, "did:example:two", third.AlsoKnownAs[0].String())

				c.Advance(web.DefaultCacheTTL)
				fourth := resolve(t, resolver, example)
				require.Equal(t, 4, o.count())
				if tt.etag != "" {
					require.Equal(t, `"v2"`, o.last().Header.Get("If-None-Match"))
				}
				if tt.lastModified != "" {
					require.Equal(t, "Fri, 02 Jan 2026 00:00:00 GMT", o.last().Header.Get("If-Modified-Since"))
				}
				require.Equal(t, third, fourth)
			})
		}

		t.Run("takes the cache lifetime from the 304", func(t *testing.T) {
			o := &origin{etag: `"v1"`, header: http.Header{"Cache-Control": {"max-age=60"}}}
			resolver, c := setup(t, o)

			resolve(t, resolver, example)
			o.set(func(o *origin) { o.header = http.Header{"Cache-Control": {"max-age=600"}} })
			c.Advance(time.Minute)
			resolve(t, resolver, example)
			require.Equal(t, 2, o.count())

			c.Advance(10*time.Minute - time.Second)
			resolve(t, resolver, example)
			require.Equal(t, 2, o.count())
			c.Advance(time.Second)
			resolve(t, resolver, example)
			require.Equal(t, 3, o.count())
		})

		t.Run("revalidates every time under no-cache", func(t *testing.T) {
			o := &origin{etag: `"v1"`, header: http.Header{"Cache-Control": {"no-cache"}}}
			resolver, _ := setup(t, o)

			resolve(t, resolver, example)
			resolve(t, resolver, example)
			resolve(t, resolver, example)
			require.Equal(t, 3, o.count())
			require.Equal(t, `"v1"`, o.last().Header.Get("If-None-Match"))
		})

		t.Run("keeps nothing under no-store", func(t *testing.T) {
			o := &origin{etag: `"v1"`, header: http.Header{"Cache-Control": {"no-store"}}}
			resolver, _ := setup(t, o)

			resolve(t, resolver, example)
			resolve(t, resolver, example)
			require.Equal(t, 2, o.count())
			require.Empty(t, o.last().Header.Get("If-None-Match"))
		})

		t.Run("keeps nothing under no-store, wherever it appears", func(t *testing.T) {
			for _, header := range []http.Header{
				{"Cache-Control": {"no-cache, no-store"}},
				{"Cache-Control": {"no-cache", "no-store"}},
				{"Cache-Control": {"max-age=3600, no-store"}},
			} {
				o := &origin{etag: `"v1"`, header: header}
				resolver, _ := setup(t, o)

				resolve(t, resolver, example)
				resolve(t, resolver, example)
				require.Equal(t, 2, o.count(), header)
				require.Empty(t, o.last().Header.Get("If-None-Match"), header)
			}
		})

		t.Run("keeps the document's Cache-Control when the 304 has none", func(t *testing.T) {
			t.Run("no-cache", func(t *testing.T) {
				o := &origin{etag: `"v1"`, header: http.Header{"Cache-Control": {"no-cache"}}}
				resolver, _ := setup(t, o)

				resolve(t, resolver, example)
				o.set(func(o *origin) { o.header = nil })
				resolve(t, resolver, example)
				resolve(t, resolver, example)
				require.Equal(t, 3, o.count())
				require.Equal(t, `"v1"`, o.last().Header.Get("If-None-Match"))
			})

			t.Run("max-age", func(t *testing.T) {
				o := &origin{etag: `"v1"`, header: http.Header{"Cache-Control": {"max-age=60"}}}
				resolver, c := setup(t, o)

				resolve(t, resolver, example)
				o.set(func(o *origin) { o.header = nil })
				c.Advance(time.Minute)
				resolve(t, resolver, example)
				require.Equal(t, 2, o.count())

				c.Advance(59 * time.Second)
				resolve(t, resolver, example)
				require.Equal(t, 2, o.count())
				c.Advance(time.Second)
				resolve(t, resolver, example)
				require.Equal(t, 3, o.count())
			})
		})

		t.Run("drops the cached document when a later response says no-store", func(t *testing.T) {
			o := &origin{etag: `"v1"`}
			resolver, c := setup(t, o)

			resolve(t, resolver, example)
			o.set(func(o *origin) { o.header = http.Header{"Cache-Control": {"no-store"}} })
			c.Advance(web.DefaultCacheTTL)
			resolve(t, resolver, example)
			require.Equal(t, `"v1"`, o.last().Header.Get("If-None-Match"))

			resolve(t, resolver, example)
			require.Equal(t, 3, o.count())
			require.Empty(t, o.last().Header.Get("If-None-Match"))
		})

		t.Run("makes a plain request when the origin gave no validator", func(t *testing.T) {
			o := &origin{}
			resolver, c := setup(t, o)

			resolve(t, resolver, example)
			c.Advance(web.DefaultCacheTTL)
			resolve(t, resolver, example)
			require.Equal(t, 2, o.count())
			require.Empty(t, o.last().Header.Get("If-None-Match"))
			require.Empty(t, o.last().Header.Get("If-Modified-Since"))
		})

		t.Run("fails on a 304 to a plain request", func(t *testing.T) {
			o := &origin{status: http.StatusNotModified}
			resolver, _ := setup(t, o)

			_, err := resolver.Resolve(t.Context(), example)
			require.ErrorContains(t, err, "unexpected status: 304")
		})

		t.Run("fails when the origin fails, and recovers with it", func(t *testing.T) {
			o := &origin{etag: `"v1"`}
			resolver, c := setup(t, o)

			resolve(t, resolver, example)
			c.Advance(web.DefaultCacheTTL)

			o.set(func(o *origin) { o.err = errors.New("connection refused") })
			_, err := resolver.Resolve(t.Context(), example)
			require.ErrorContains(t, err, "connection refused")

			o.set(func(o *origin) { o.err = nil; o.status = http.StatusBadGateway })
			_, err = resolver.Resolve(t.Context(), example)
			require.ErrorContains(t, err, "unexpected status: 502")

			// The stale document was kept, so recovery is still a 304.
			o.set(func(o *origin) { o.status = 0 })
			resolve(t, resolver, example)
			require.Equal(t, 4, o.count())
			require.Equal(t, `"v1"`, o.last().Header.Get("If-None-Match"))
		})
	})

	// Two resolutions revalidate the same stale document. The origin answers
	// the first with a 304, changes the document, and answers the second with
	// the new one; the 304 arrives last. It must not put the old document
	// back.
	t.Run("a late 304 does not replace a newer document", func(t *testing.T) {
		body := func(alsoKnownAs string) io.ReadCloser {
			doc := did.NewDocument(example)
			doc.AlsoKnownAs = []did.URL{mustParseURL(t, alsoKnownAs)}
			b, err := json.Marshal(doc)
			require.NoError(t, err)
			return io.NopCloser(bytes.NewReader(b))
		}
		var mu sync.Mutex
		requests := 0
		notModifiedSent := make(chan struct{})
		deliverNotModified := make(chan struct{})
		transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			mu.Lock()
			requests++
			n := requests
			mu.Unlock()
			switch n {
			case 1:
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Etag": {`"v1"`}}, Body: body("did:example:one")}, nil
			case 2:
				close(notModifiedSent)
				<-deliverNotModified
				return &http.Response{StatusCode: http.StatusNotModified, Header: http.Header{"Etag": {`"v1"`}}, Body: http.NoBody}, nil
			case 3:
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Etag": {`"v2"`}}, Body: body("did:example:two")}, nil
			default:
				return nil, fmt.Errorf("unexpected request %d", n)
			}
		})
		c := newClock()
		resolver, err := web.NewResolver(web.WithTransport(transport), web.WithClock(c.Now))
		require.NoError(t, err)

		resolve(t, resolver, example)
		c.Advance(web.DefaultCacheTTL)

		late := make(chan did.Document)
		go func() {
			doc, err := resolver.Resolve(t.Context(), example)
			if err != nil {
				close(late)
				return
			}
			late <- doc
		}()
		<-notModifiedSent
		second := resolve(t, resolver, example)
		require.Equal(t, "did:example:two", second.AlsoKnownAs[0].String())
		close(deliverNotModified)
		doc, ok := <-late
		require.True(t, ok, "the late resolution failed")
		require.Equal(t, "did:example:one", doc.AlsoKnownAs[0].String())

		third := resolve(t, resolver, example)
		require.Equal(t, "did:example:two", third.AlsoKnownAs[0].String())
		mu.Lock()
		defer mu.Unlock()
		require.Equal(t, 3, requests)
	})

	t.Run("handles concurrent resolution", func(t *testing.T) {
		o := &origin{etag: `"v1"`, header: http.Header{"Cache-Control": {"no-cache"}}}
		resolver, _ := setup(t, o, web.WithCacheSize(4))

		var wg sync.WaitGroup
		for i := range 64 {
			wg.Go(func() {
				d := did.MustParse(fmt.Sprintf("did:web:host%d.example", i%8))
				doc, err := resolver.Resolve(t.Context(), d)
				require.NoError(t, err)
				require.Equal(t, d, doc.ID)
			})
		}
		wg.Wait()
	})
}

func TestCacheOptions(t *testing.T) {
	tests := []struct {
		name   string
		option web.Option
		want   string
	}{
		{"negative cache TTL", web.WithCacheTTL(-time.Second), "cache TTL cannot be negative"},
		{"zero max cache TTL", web.WithMaxCacheTTL(0), "max cache TTL must be positive"},
		{"zero cache size", web.WithCacheSize(0), "cache size must be positive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := web.NewResolver(tt.option)
			require.ErrorContains(t, err, tt.want)
		})
	}
}
