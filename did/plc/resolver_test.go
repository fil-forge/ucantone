package plc_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

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

// jsonResponse builds a canned HTTP response with the given status and body.
func stringResponse(status int, body string) *http.Response {
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
			return stringResponse(http.StatusOK, string(body)), nil
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
			return stringResponse(http.StatusOK, "{}"), nil
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
			return stringResponse(http.StatusNotFound, "not found"), nil
		})
		r, err := plc.NewResolver(endpoint, plc.WithTransport(rt))
		require.NoError(t, err)

		_, err = r.Resolve(t.Context(), d)
		require.ErrorContains(t, err, "unexpected status")
	})

	t.Run("errors on invalid JSON", func(t *testing.T) {
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return stringResponse(http.StatusOK, "this is not json"), nil
		})
		r, err := plc.NewResolver(endpoint, plc.WithTransport(rt))
		require.NoError(t, err)

		_, err = r.Resolve(t.Context(), d)
		require.ErrorContains(t, err, "parsing DID document JSON")
	})
}
