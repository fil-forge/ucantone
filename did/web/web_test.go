package web_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/web"
	"github.com/stretchr/testify/require"
)

func TestNewResolver(t *testing.T) {
	t.Run("creates resolver with default timeout", func(t *testing.T) {
		resolver, err := web.NewResolver()
		require.NoError(t, err)
		require.NotNil(t, resolver)
	})

	t.Run("creates resolver with custom timeout", func(t *testing.T) {
		resolver, err := web.NewResolver(web.WithTimeout(5*time.Second), web.WithInsecure(true))
		require.NoError(t, err)
		require.NotNil(t, resolver)
	})

	t.Run("fails with zero timeout", func(t *testing.T) {
		resolver, err := web.NewResolver(web.WithTimeout(0))
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout cannot be zero")
		require.Nil(t, resolver)
	})
}

// roundTripFunc implements http.RoundTripper using a plain function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mustParseURL(t *testing.T, s string) did.URL {
	t.Helper()
	u, err := did.ParseURL(s)
	require.NoError(t, err)
	return u
}

func TestResolver(t *testing.T) {
	t.Run("resolves a pathless DID", func(t *testing.T) {
		doc := did.NewDocument(did.MustParse("did:web:example.com"))
		doc.AlsoKnownAs = []did.URL{mustParseURL(t, "did:example:abc123")}
		body, err := json.Marshal(doc)
		require.NoError(t, err)

		transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			require.Equal(t, "https://example.com/.well-known/did.json", r.URL.String())
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, nil
		})

		resolver, err := web.NewResolver(web.WithTransport(transport))
		require.NoError(t, err)

		result, resolveErr := resolver.Resolve(t.Context(), did.MustParse("did:web:example.com"))
		require.NoError(t, resolveErr)
		require.Equal(t, did.MustParse("did:web:example.com"), result.ID)
		require.Equal(t, []did.URL{mustParseURL(t, "did:example:abc123")}, result.AlsoKnownAs)
	})

	t.Run("resolves a pathful DID", func(t *testing.T) {
		doc := did.NewDocument(did.MustParse("did:web:example.com:users:alice"))
		doc.AlsoKnownAs = []did.URL{mustParseURL(t, "did:example:abc123")}
		body, err := json.Marshal(doc)
		require.NoError(t, err)

		transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			require.Equal(t, "https://example.com/users/alice/did.json", r.URL.String())
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, nil
		})

		resolver, err := web.NewResolver(web.WithTransport(transport))
		require.NoError(t, err)

		result, resolveErr := resolver.Resolve(t.Context(), did.MustParse("did:web:example.com:users:alice"))
		require.NoError(t, resolveErr)
		require.Equal(t, did.MustParse("did:web:example.com:users:alice"), result.ID)
		require.Equal(t, []did.URL{mustParseURL(t, "did:example:abc123")}, result.AlsoKnownAs)
	})

	t.Run("resolves a portly DID", func(t *testing.T) {
		doc := did.NewDocument(did.MustParse("did:web:example.com%3A3000"))
		doc.AlsoKnownAs = []did.URL{mustParseURL(t, "did:example:abc123")}
		body, err := json.Marshal(doc)
		require.NoError(t, err)

		transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			require.Equal(t, "https://example.com:3000/.well-known/did.json", r.URL.String())
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, nil
		})

		resolver, err := web.NewResolver(web.WithTransport(transport))
		require.NoError(t, err)

		result, resolveErr := resolver.Resolve(t.Context(), did.MustParse("did:web:example.com%3A3000"))
		require.NoError(t, resolveErr)
		require.Equal(t, did.MustParse("did:web:example.com%3A3000"), result.ID)
		require.Equal(t, []did.URL{mustParseURL(t, "did:example:abc123")}, result.AlsoKnownAs)
	})

	t.Run("resolves a DID whose port is escaped in lower case", func(t *testing.T) {
		id := did.MustParse("did:web:example.com%3a3000")
		body, err := json.Marshal(did.NewDocument(id))
		require.NoError(t, err)

		transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			require.Equal(t, "https://example.com:3000/.well-known/did.json", r.URL.String())
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, nil
		})

		resolver, err := web.NewResolver(web.WithTransport(transport))
		require.NoError(t, err)

		result, resolveErr := resolver.Resolve(t.Context(), id)
		require.NoError(t, resolveErr)
		require.Equal(t, id, result.ID)
	})

	t.Run("resolves a DID whose path has percent-encoded characters", func(t *testing.T) {
		u, err := url.Parse("https://example.com/a%20b/c:d")
		require.NoError(t, err)
		id, err := web.New(*u)
		require.NoError(t, err)
		require.Equal(t, "did:web:example.com:a%20b:c%3Ad", id.String())

		body, err := json.Marshal(did.NewDocument(id))
		require.NoError(t, err)

		transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			require.Equal(t, "https://example.com/a%20b/c%3Ad/did.json", r.URL.String())
			require.Equal(t, "/a b/c:d/did.json", r.URL.Path)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, nil
		})

		resolver, err := web.NewResolver(web.WithTransport(transport))
		require.NoError(t, err)

		result, resolveErr := resolver.Resolve(t.Context(), id)
		require.NoError(t, resolveErr)
		require.Equal(t, id, result.ID)
	})

	t.Run("refuses a DID whose host is an IP address", func(t *testing.T) {
		transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			t.Fatalf("no request expected, got %s", r.URL)
			return nil, nil
		})

		resolver, err := web.NewResolver(web.WithTransport(transport), web.WithInsecure(true))
		require.NoError(t, err)

		_, resolveErr := resolver.Resolve(t.Context(), did.MustParse("did:web:127.0.0.1%3A3000"))
		require.ErrorContains(t, resolveErr, "is an IP address")
	})

	t.Run("returns error on HTTP 404", func(t *testing.T) {
		transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})

		resolver, err := web.NewResolver(web.WithTransport(transport))
		require.NoError(t, err)

		_, resolveErr := resolver.Resolve(t.Context(), did.MustParse("did:web:example.com"))
		require.ErrorContains(t, resolveErr, "unexpected status: 404")
	})

	t.Run("returns error on invalid JSON", func(t *testing.T) {
		transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader("invalid json")),
			}, nil
		})

		resolver, err := web.NewResolver(web.WithTransport(transport))
		require.NoError(t, err)

		_, resolveErr := resolver.Resolve(t.Context(), did.MustParse("did:web:example.com"))
		require.ErrorContains(t, resolveErr, "parsing DID document JSON")
	})

	t.Run("returns error when pattern blocks resolution", func(t *testing.T) {
		resolver, err := web.NewResolver(web.WithPatterns("*.example.com"))
		require.NoError(t, err)

		_, resolveErr := resolver.Resolve(t.Context(), did.MustParse("did:web:notfound.com"))
		require.ErrorContains(t, resolveErr, "resolution of did:web:notfound.com via HTTP not permitted")
	})

	t.Run("allows insecure HTTP resolution", func(t *testing.T) {
		doc := did.NewDocument(did.MustParse("did:web:example.com"))
		body, err := json.Marshal(doc)
		require.NoError(t, err)

		transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			require.Equal(t, "http", r.URL.Scheme)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, nil
		})

		resolver, err := web.NewResolver(web.WithInsecure(true), web.WithTransport(transport))
		require.NoError(t, err)

		result, resolveErr := resolver.Resolve(t.Context(), did.MustParse("did:web:example.com"))
		require.NoError(t, resolveErr)
		require.Equal(t, did.MustParse("did:web:example.com"), result.ID)
	})

	t.Run("returns error when timeout is exceeded", func(t *testing.T) {
		doc := did.NewDocument(did.MustParse("did:web:example.com"))
		body, err := json.Marshal(doc)
		require.NoError(t, err)

		// Responds after 100ms, or immediately if context is cancelled.
		transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			select {
			// The roundtripper is synchronous, so we have to cooperate.
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case <-time.After(100 * time.Millisecond):
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(bytes.NewReader(body)),
				}, nil
			}
		})

		slowResolver, err := web.NewResolver(web.WithTimeout(5*time.Millisecond), web.WithTransport(transport))
		require.NoError(t, err)
		_, resolveErr := slowResolver.Resolve(t.Context(), did.MustParse("did:web:example.com"))
		require.ErrorContains(t, resolveErr, "context deadline exceeded")

		fastResolver, err := web.NewResolver(web.WithTimeout(time.Second), web.WithTransport(transport))
		require.NoError(t, err)
		result, resolveErr := fastResolver.Resolve(t.Context(), did.MustParse("did:web:example.com"))
		require.NoError(t, resolveErr)
		require.Equal(t, did.MustParse("did:web:example.com"), result.ID)
	})

	// redirectingTransport redirects the well-known path on example.com to
	// redirect.example and serves the document there. It records every URL
	// requested.
	redirectingTransport := func(t *testing.T, requested *[]string) roundTripFunc {
		doc := did.NewDocument(did.MustParse("did:web:example.com"))
		body, err := json.Marshal(doc)
		require.NoError(t, err)

		return func(r *http.Request) (*http.Response, error) {
			*requested = append(*requested, r.URL.String())
			if r.URL.Host == "example.com" {
				return &http.Response{
					StatusCode: http.StatusFound,
					Header:     http.Header{"Location": []string{"https://redirect.example/did.json"}},
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, nil
		}
	}

	t.Run("returns error on redirect by default", func(t *testing.T) {
		var requested []string
		resolver, err := web.NewResolver(web.WithTransport(redirectingTransport(t, &requested)))
		require.NoError(t, err)

		_, resolveErr := resolver.Resolve(t.Context(), did.MustParse("did:web:example.com"))
		require.ErrorContains(t, resolveErr, `redirect to "https://redirect.example/did.json" not followed`)
		require.Equal(t, []string{"https://example.com/.well-known/did.json"}, requested)
	})

	t.Run("follows redirects when enabled", func(t *testing.T) {
		var requested []string
		resolver, err := web.NewResolver(
			web.WithFollowRedirects(true),
			web.WithTransport(redirectingTransport(t, &requested)),
		)
		require.NoError(t, err)

		result, resolveErr := resolver.Resolve(t.Context(), did.MustParse("did:web:example.com"))
		require.NoError(t, resolveErr)
		require.Equal(t, did.MustParse("did:web:example.com"), result.ID)
		require.Equal(t, []string{
			"https://example.com/.well-known/did.json",
			"https://redirect.example/did.json",
		}, requested)
	})
}
