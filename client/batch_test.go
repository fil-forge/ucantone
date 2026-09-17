package client_test

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"

	"github.com/fil-forge/ucantone/client"
	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/execution/dispatcher"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestHTTPClientBatch(t *testing.T) {
	service := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)

	srv := server.NewHTTP(service)
	srv.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
		return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
	})

	c, err := client.NewHTTP(
		testutil.Must(url.Parse("http://localhost"))(t),
		client.WithHTTPClient(&http.Client{Transport: srv}),
	)
	require.NoError(t, err)

	echo := func(t *testing.T, message string) ucan.Invocation {
		inv, err := invocation.Invoke(
			alice,
			alice.DID(),
			testutil.TestEchoCommand,
			datamodel.Map{"message": message},
			invocation.WithAudience(service.DID()),
		)
		require.NoError(t, err)
		return inv
	}

	t.Run("batch execution round trip", func(t *testing.T) {
		first := echo(t, "one")
		second := echo(t, "two")
		// no handler is registered for this command, so its receipt is a failure
		unhandled, err := invocation.Invoke(
			alice,
			alice.DID(),
			testutil.ConsoleLogCommand,
			datamodel.Map{},
			invocation.WithAudience(service.DID()),
		)
		require.NoError(t, err)

		res, err := c.ExecuteBatch(batch.NewRequest(t.Context(), []ucan.Invocation{first, second, unhandled}))
		require.NoError(t, err)

		require.Len(t, res.Receipts(), 3)
		for i, inv := range []ucan.Invocation{first, second, unhandled} {
			require.Equal(t, inv.Task().Link(), res.Receipts()[i].Ran())
		}

		for inv, want := range map[ucan.Invocation]string{first: "one", second: "two"} {
			rcpt, ok := res.Receipt(inv.Task().Link())
			require.True(t, ok)
			o, x := rcpt.Out().Unpack()
			require.Nil(t, x)
			require.Equal(t, want, testutil.ResultMap(t, o)["message"])
		}

		rcpt, ok := res.Receipt(unhandled.Task().Link())
		require.True(t, ok)
		_, x := rcpt.Out().Unpack()
		require.NotNil(t, x)
		var model edm.ErrorModel
		require.NoError(t, model.UnmarshalCBOR(bytes.NewReader(x)))
		require.Equal(t, dispatcher.HandlerNotFoundErrorName, model.ErrorName)

		// the response metadata is the whole response container
		require.Len(t, res.Metadata().Receipts(), 3)
	})

	t.Run("context invocations are not answered", func(t *testing.T) {
		inv := echo(t, "hello")
		// addressed to alice, so the server skips it; it travels as context only
		cause, err := invocation.Invoke(alice, alice.DID(), testutil.ConsoleLogCommand, datamodel.Map{})
		require.NoError(t, err)

		res, err := c.ExecuteBatch(batch.NewRequest(t.Context(), []ucan.Invocation{inv}, batch.WithInvocations(cause)))
		require.NoError(t, err)
		require.Len(t, res.Receipts(), 1)
		_, ok := res.Receipt(cause.Task().Link())
		require.False(t, ok)
	})

	t.Run("missing receipt is an error", func(t *testing.T) {
		// the server skips invocations addressed to someone else, so this one
		// never gets a receipt
		elsewhere, err := invocation.Invoke(
			alice,
			alice.DID(),
			testutil.TestEchoCommand,
			datamodel.Map{"message": "lost"},
			invocation.WithAudience(testutil.RandomDID(t)),
		)
		require.NoError(t, err)

		_, err = c.ExecuteBatch(batch.NewRequest(t.Context(), []ucan.Invocation{echo(t, "found"), elsewhere}))
		require.ErrorContains(t, err, "missing receipt for task: "+elsewhere.Task().Link().String())
	})

	t.Run("empty batch is an error", func(t *testing.T) {
		_, err := c.ExecuteBatch(batch.NewRequest(t.Context(), nil))
		require.ErrorContains(t, err, "no invocations")
	})

	t.Run("single execution carries request metadata", func(t *testing.T) {
		var seen ucan.Container
		srv := server.NewHTTP(service)
		srv.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			seen = req.Metadata()
			return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
		})
		c, err := client.NewHTTP(
			testutil.Must(url.Parse("http://localhost"))(t),
			client.WithHTTPClient(&http.Client{Transport: srv}),
		)
		require.NoError(t, err)

		inv := echo(t, "hello")
		cause, err := invocation.Invoke(alice, alice.DID(), testutil.ConsoleLogCommand, datamodel.Map{})
		require.NoError(t, err)

		res, err := c.Execute(execution.NewRequest(t.Context(), inv, execution.WithInvocations(cause)))
		require.NoError(t, err)
		require.Equal(t, inv.Task().Link(), res.Receipt().Ran())

		// the handler sees the invocation and its context invocation
		require.NotNil(t, seen)
		links := []string{}
		for _, i := range seen.Invocations() {
			links = append(links, i.Link().String())
		}
		require.Contains(t, links, cause.Link().String())
		require.Contains(t, links, inv.Link().String())
	})
}
