package web_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
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
		resolver, err := web.NewResolver(web.WithTimeout(5*time.Second), web.WithInsecure())
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

func TestResolver(t *testing.T) {
	t.Run("resolves a pathless DID", func(t *testing.T) {
		doc := did.NewDocument(did.MustParse("did:web:example.com"))
		doc.AlsoKnownAs = []did.DID{did.MustParse("did:example:abc123")}
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
		require.Equal(t, []did.DID{did.MustParse("did:example:abc123")}, result.AlsoKnownAs)
	})

	t.Run("resolves a pathful DID", func(t *testing.T) {
		doc := did.NewDocument(did.MustParse("did:web:example.com:users:alice"))
		doc.AlsoKnownAs = []did.DID{did.MustParse("did:example:abc123")}
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
		require.Equal(t, []did.DID{did.MustParse("did:example:abc123")}, result.AlsoKnownAs)
	})

	t.Run("resolves a portly DID", func(t *testing.T) {
		doc := did.NewDocument(did.MustParse("did:web:example.com%3A3000"))
		doc.AlsoKnownAs = []did.DID{did.MustParse("did:example:abc123")}
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
		require.Equal(t, []did.DID{did.MustParse("did:example:abc123")}, result.AlsoKnownAs)
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

		resolver, err := web.NewResolver(web.WithInsecure(), web.WithTransport(transport))
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
			case <-time.After(10 * time.Millisecond):
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

		fastResolver, err := web.NewResolver(web.WithTimeout(20*time.Millisecond), web.WithTransport(transport))
		require.NoError(t, err)
		result, resolveErr := fastResolver.Resolve(t.Context(), did.MustParse("did:web:example.com"))
		require.NoError(t, resolveErr)
		require.Equal(t, did.MustParse("did:web:example.com"), result.ID)
	})
}
