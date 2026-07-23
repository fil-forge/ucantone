package plc_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/stretchr/testify/require"
)

// roundTripperFunc adapts a function to http.RoundTripper so tests can serve
// canned responses and inspect the outgoing request.
type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// mockResponse builds a canned HTTP response with the given status and body.
func mockResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
}

func mustParseURL(t *testing.T, raw string) url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return *u
}

func TestResolve(t *testing.T) {
	endpoint := mustParseURL(t, "https://plc.example")
	d, err := did.Parse("did:plc:7iza6de2dwap2sbkpav7c6c6")
	require.NoError(t, err)

	t.Run("resolves a did:plc document", func(t *testing.T) {
		want := did.Document{ID: d}
		body, err := json.Marshal(want)
		require.NoError(t, err)

		var gotReq *http.Request
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			return mockResponse(http.StatusOK, string(body)), nil
		})
		r, err := plc.NewResolver(endpoint, plc.WithTransport(rt))
		require.NoError(t, err)

		doc, err := r.Resolve(t.Context(), d)
		require.NoError(t, err)
		require.Equal(t, d, doc.ID)

		require.Equal(t, "GET", gotReq.Method)
		require.True(t, strings.HasSuffix(gotReq.URL.Path, d.String()), "path %s should end with %s", gotReq.URL.Path, d.String())
	})

	t.Run("rejects a non-plc DID without making a request", func(t *testing.T) {
		called := false
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return mockResponse(http.StatusOK, "{}"), nil
		})
		r, err := plc.NewResolver(endpoint, plc.WithTransport(rt))
		require.NoError(t, err)

		web, err := did.Parse("did:web:example.com")
		require.NoError(t, err)
		_, err = r.Resolve(t.Context(), web)
		require.ErrorContains(t, err, "expected plc")
		require.False(t, called, "no HTTP request should be made for a non-plc DID")
	})

	t.Run("errors on non-200 status", func(t *testing.T) {
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return mockResponse(http.StatusNotFound, "not found"), nil
		})
		r, err := plc.NewResolver(endpoint, plc.WithTransport(rt))
		require.NoError(t, err)

		_, err = r.Resolve(t.Context(), d)
		require.ErrorContains(t, err, "unexpected status")
	})

	t.Run("errors on invalid JSON", func(t *testing.T) {
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return mockResponse(http.StatusOK, "this is not json"), nil
		})
		r, err := plc.NewResolver(endpoint, plc.WithTransport(rt))
		require.NoError(t, err)

		_, err = r.Resolve(t.Context(), d)
		require.ErrorContains(t, err, "parsing DID document JSON")
	})
}

// mapCache is a minimal plc.Cache implementation for tests. It records the
// expiration duration of the most recent Set.
type mapCache struct {
	items       map[string]interface{}
	lastSetDura time.Duration
}

func newMapCache() *mapCache {
	return &mapCache{items: map[string]interface{}{}}
}

func (c *mapCache) Get(k string) (interface{}, bool) {
	v, ok := c.items[k]
	return v, ok
}

func (c *mapCache) Set(k string, x interface{}, d time.Duration) {
	c.items[k] = x
	c.lastSetDura = d
}

func TestResolveWithCache(t *testing.T) {
	endpoint := mustParseURL(t, "https://plc.example")
	d, err := did.Parse("did:plc:7iza6de2dwap2sbkpav7c6c6")
	require.NoError(t, err)

	body, err := json.Marshal(did.Document{ID: d})
	require.NoError(t, err)

	t.Run("populates cache and revalidates with If-None-Match", func(t *testing.T) {
		const etag = `"abc123"`
		var reqs []*http.Request
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			reqs = append(reqs, req)
			resp := mockResponse(http.StatusOK, string(body))
			resp.Header.Set("ETag", etag)
			return resp, nil
		})
		c := newMapCache()
		r, err := plc.NewResolver(endpoint, plc.WithTransport(rt), plc.WithCache(c))
		require.NoError(t, err)

		doc, err := r.Resolve(t.Context(), d)
		require.NoError(t, err)
		require.Equal(t, d, doc.ID)

		// The document should now be cached.
		_, found := c.Get(d.String())
		require.True(t, found, "document should be cached")
		require.Len(t, reqs, 1)
		require.Empty(t, reqs[0].Header.Get("If-None-Match"), "first request must not send If-None-Match")
		// A second resolution should revalidate with the stored ETag.
		_, err = r.Resolve(t.Context(), d)
		require.NoError(t, err)
		require.Len(t, reqs, 2)
		require.Equal(t, etag, reqs[1].Header.Get("If-None-Match"))
	})

	t.Run("returns cached document on 304 Not Modified", func(t *testing.T) {
		const etag = `"abc123"`
		call := 0
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			call++
			if call == 1 {
				resp := mockResponse(http.StatusOK, string(body))
				resp.Header.Set("ETag", etag)
				return resp, nil
			}
			return mockResponse(http.StatusNotModified, ""), nil
		})
		c := newMapCache()
		r, err := plc.NewResolver(endpoint, plc.WithTransport(rt), plc.WithCache(c))
		require.NoError(t, err)

		_, err = r.Resolve(t.Context(), d)
		require.NoError(t, err)

		doc, err := r.Resolve(t.Context(), d)
		require.NoError(t, err)
		require.Equal(t, d, doc.ID, "304 should return the cached document")
	})

	t.Run("passes the configured expiration to the cache", func(t *testing.T) {
		const etag = `"abc123"`
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			resp := mockResponse(http.StatusOK, string(body))
			resp.Header.Set("ETag", etag)
			return resp, nil
		})
		c := newMapCache()
		ttl := 5 * time.Minute
		r, err := plc.NewResolver(endpoint, plc.WithTransport(rt), plc.WithCache(c), plc.WithCacheExpiration(ttl))
		require.NoError(t, err)

		_, err = r.Resolve(t.Context(), d)
		require.NoError(t, err)
		require.Equal(t, ttl, c.lastSetDura)
	})

	t.Run("does not cache when no ETag is returned", func(t *testing.T) {
		var reqs []*http.Request
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			reqs = append(reqs, req)
			return mockResponse(http.StatusOK, string(body)), nil
		})
		c := newMapCache()
		r, err := plc.NewResolver(endpoint, plc.WithTransport(rt), plc.WithCache(c))
		require.NoError(t, err)

		_, err = r.Resolve(t.Context(), d)
		require.NoError(t, err)
		_, found := c.Get(d.String())
		require.False(t, found, "document without an ETag should not be cached")

		_, err = r.Resolve(t.Context(), d)
		require.NoError(t, err)
		require.Len(t, reqs, 2)
		require.Empty(t, reqs[1].Header.Get("If-None-Match"), "no If-None-Match without a cached ETag")
	})
}
