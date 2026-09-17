package client_test

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
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

// countingBody reports whether it was closed, so a test can prove a response
// body is released rather than leaked.
type countingBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *countingBody) Close() error {
	b.closed.Store(true)
	return nil
}

// bodyWatcher wraps a round tripper and records every response body it hands
// back, so the test can assert on them after the call returns.
type bodyWatcher struct {
	inner  http.RoundTripper
	mu     sync.Mutex
	bodies []*countingBody
}

func (w *bodyWatcher) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := w.inner.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	body := &countingBody{Reader: res.Body}
	w.mu.Lock()
	w.bodies = append(w.bodies, body)
	w.mu.Unlock()
	res.Body = body
	return res, nil
}

func (w *bodyWatcher) allClosed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range w.bodies {
		if !b.closed.Load() {
			return false
		}
	}
	return len(w.bodies) > 0
}

// TestHTTPClientBatchClosesBodyOnError pins that a failed batch still releases
// its response body. A batch whose invocation is addressed elsewhere gets no
// receipt and so fails by design, which makes this the routine path rather
// than an exotic one — leaking there leaks a connection per call.
func TestHTTPClientBatchClosesBodyOnError(t *testing.T) {
	service := testutil.RandomIssuer(t)
	elsewhere := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)

	srv := server.NewHTTP(service)
	srv.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
		return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
	})

	watcher := &bodyWatcher{inner: srv}
	c, err := client.NewHTTP(
		testutil.Must(url.Parse("http://localhost"))(t),
		client.WithHTTPClient(&http.Client{Transport: watcher}),
	)
	require.NoError(t, err)

	// Addressed to another service, so this server skips it and answers with
	// no receipt for the task.
	inv, err := invocation.Invoke(
		alice,
		alice.DID(),
		testutil.TestEchoCommand,
		datamodel.Map{"message": "for someone else"},
		invocation.WithAudience(elsewhere.DID()),
	)
	require.NoError(t, err)

	_, err = c.ExecuteBatch(batch.NewRequest(t.Context(), []ucan.Invocation{inv}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing receipt")
	require.True(t, watcher.allClosed(), "a failed batch must not leak its response body")
}
