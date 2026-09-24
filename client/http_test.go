package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestHTTPClient(t *testing.T) {
	service := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)

	t.Run("invocation execution round trip", func(t *testing.T) {
		server := server.NewHTTP(service)

		server.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
		})

		c, err := client.NewHTTP(
			testutil.Must(url.Parse("http://localhost"))(t),
			client.WithHTTPClient(&http.Client{Transport: server}),
		)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			alice,
			alice.DID(),
			testutil.TestEchoCommand,
			datamodel.Map{"message": "echo!"},
			invocation.WithAudience(service.DID()),
		)
		require.NoError(t, err)

		res, err := c.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)

		o, x := res.Receipt().Out().Unpack()
		require.Nil(t, x)
		require.NotNil(t, o)
		require.Equal(t, "echo!", testutil.ResultMap(t, o)["message"])
	})
}

func TestHTTPClientRequestContext(t *testing.T) {
	service := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)

	srv := server.NewHTTP(service)
	srv.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
		return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
	})
	echo := func(t *testing.T) ucan.Invocation {
		inv, err := invocation.Invoke(
			alice,
			alice.DID(),
			testutil.TestEchoCommand,
			datamodel.Map{"message": "echo!"},
			invocation.WithAudience(service.DID()),
		)
		require.NoError(t, err)
		return inv
	}

	t.Run("the request carries the caller's context", func(t *testing.T) {
		type key struct{}
		var got any
		c, err := client.NewHTTP(
			testutil.Must(url.Parse("http://localhost"))(t),
			client.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				got = r.Context().Value(key{})
				return srv.RoundTrip(r)
			})}),
		)
		require.NoError(t, err)

		ctx := context.WithValue(t.Context(), key{}, "caller")
		_, err = c.Execute(execution.NewRequest(ctx, echo(t)))
		require.NoError(t, err)
		require.Equal(t, "caller", got)
	})

	t.Run("a canceled context aborts the request", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("the request reached the server")
		}))
		defer ts.Close()
		c, err := client.NewHTTP(testutil.Must(url.Parse(ts.URL))(t))
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err = c.Execute(execution.NewRequest(ctx, echo(t)))
		require.ErrorIs(t, err, context.Canceled)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
