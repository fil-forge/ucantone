package server_test

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestHTTPServer(t *testing.T) {
	service := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)

	t.Run("invocation execution round trip", func(t *testing.T) {
		server := server.NewHTTP(service, server.WithReceiptTimestamps(true))

		var messages []ipld.Any
		server.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
			msg := testutil.ArgsMap(t, req.Invocation())["message"]
			t.Log(msg)
			messages = append(messages, msg)
			return res.SetSuccess(datamodel.Map{})
		})
		server.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
		})

		logInv, err := invocation.Invoke(
			alice,
			alice.DID(),
			testutil.ConsoleLogCommand,
			datamodel.Map{"message": "Hello, World!"},
			invocation.WithAudience(service.DID()),
		)
		require.NoError(t, err)

		ct := container.New(container.WithInvocations(logInv))

		r, w := io.Pipe()
		go func(ct *container.Container, w *io.PipeWriter) {
			err := ct.MarshalCBOR(w)
			w.CloseWithError(err)
		}(ct, w)

		req := http.Request{Header: http.Header{}, Body: r}
		req.Header.Set("Content-Type", dagcbor.ContentType)

		resp, err := server.RoundTrip(&req)
		require.NoError(t, err)

		ctResp := container.Container{}
		err = ctResp.UnmarshalCBOR(resp.Body)
		require.NoError(t, err)

		require.Len(t, ctResp.Receipts(), 1)

		_, x := ctResp.Receipts()[0].Out().Unpack()
		require.Nil(t, x)

		require.Len(t, messages, 1)
		require.Equal(t, "Hello, World!", messages[0])

		echoInv, err := invocation.Invoke(
			alice,
			alice.DID(),
			testutil.TestEchoCommand,
			datamodel.Map{"message": "echo!"},
			invocation.WithAudience(service.DID()),
		)
		require.NoError(t, err)

		ct = container.New(container.WithInvocations(echoInv))

		r, w = io.Pipe()
		go func(ct *container.Container, w *io.PipeWriter) {
			err := ct.MarshalCBOR(w)
			w.CloseWithError(err)
		}(ct, w)

		req = http.Request{Header: http.Header{}, Body: r}
		req.Header.Set("Content-Type", dagcbor.ContentType)

		resp, err = server.RoundTrip(&req)
		require.NoError(t, err)

		ctResp = container.Container{}
		err = ctResp.UnmarshalCBOR(resp.Body)
		require.NoError(t, err)

		require.Len(t, ctResp.Receipts(), 1)
		rcpt := ctResp.Receipts()[0]

		require.NotNil(t, rcpt.IssuedAt())
		// we can't assert an exact timestamp, but check that it is recent
		require.GreaterOrEqual(t, int64(*rcpt.IssuedAt()), time.Now().Add(-time.Second).Unix())

		o, x := rcpt.Out().Unpack()
		require.NotNil(t, o)
		require.Nil(t, x)
		t.Log(o)

		require.Len(t, messages, 1) // should not have changed
		require.Equal(t, "echo!", testutil.ResultMap(t, o)["message"])
	})
}

func TestHTTPServerBatch(t *testing.T) {
	service := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)

	t.Run("batch execution", func(t *testing.T) {
		server := server.NewHTTP(service)

		var attached ucan.Invocation
		server.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			// attach a token to the response, as a handler issuing a claim would
			claim, err := invocation.Invoke(service, service.DID(), testutil.ConsoleLogCommand, datamodel.Map{})
			if err != nil {
				return err
			}
			attached = claim
			if err := res.SetMetadata(container.New(container.WithInvocations(claim))); err != nil {
				return err
			}
			return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
		})

		addressed, err := invocation.Invoke(
			alice,
			alice.DID(),
			testutil.TestEchoCommand,
			datamodel.Map{"message": "echo!"},
			invocation.WithAudience(service.DID()),
		)
		require.NoError(t, err)
		elsewhere, err := invocation.Invoke(
			alice,
			alice.DID(),
			testutil.TestEchoCommand,
			datamodel.Map{"message": "not for you"},
			invocation.WithAudience(testutil.RandomDID(t)),
		)
		require.NoError(t, err)

		res, err := server.ExecuteBatch(batch.NewRequest(t.Context(), []ucan.Invocation{elsewhere, addressed}))
		require.NoError(t, err)

		rcpt, ok := res.Receipt(addressed.Task().Link())
		require.True(t, ok)
		o, x := rcpt.Out().Unpack()
		require.Nil(t, x)
		require.Equal(t, "echo!", testutil.ResultMap(t, o)["message"])

		_, ok = res.Receipt(elsewhere.Task().Link())
		require.False(t, ok)

		require.NotNil(t, res.Metadata())
		require.Len(t, res.Metadata().Invocations(), 1)
		require.Equal(t, attached.Link(), res.Metadata().Invocations()[0].Link())
	})

	t.Run("batch handlers share one metadata container", func(t *testing.T) {
		server := server.NewHTTP(service)

		var seen []ucan.Container
		server.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			seen = append(seen, req.Metadata())
			return res.SetSuccess(datamodel.Map{})
		})

		var invs []ucan.Invocation
		for range 3 {
			inv, err := invocation.Invoke(alice, alice.DID(), testutil.TestEchoCommand, datamodel.Map{}, invocation.WithAudience(service.DID()))
			require.NoError(t, err)
			invs = append(invs, inv)
		}

		_, err := server.ExecuteBatch(batch.NewRequest(t.Context(), invs))
		require.NoError(t, err)

		require.Len(t, seen, 3)
		require.Same(t, seen[0], seen[1])
		require.Same(t, seen[0], seen[2])
	})

	t.Run("batch addressed entirely elsewhere runs no handler", func(t *testing.T) {
		server := server.NewHTTP(service)

		calls := 0
		server.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			calls++
			return res.SetSuccess(datamodel.Map{})
		})

		var invs []ucan.Invocation
		for range 2 {
			inv, err := invocation.Invoke(alice, alice.DID(), testutil.TestEchoCommand, datamodel.Map{}, invocation.WithAudience(testutil.RandomDID(t)))
			require.NoError(t, err)
			invs = append(invs, inv)
		}

		res, err := server.ExecuteBatch(batch.NewRequest(t.Context(), invs))
		require.NoError(t, err)

		var receipts []ucan.Receipt
		for _, inv := range invs {
			if rcpt, ok := res.Receipt(inv.Task().Link()); ok {
				receipts = append(receipts, rcpt)
			}
		}
		require.Equal(t, []any{0, []ucan.Receipt(nil), ucan.Container(nil)}, []any{calls, receipts, res.Metadata()})
	})

	t.Run("empty batch", func(t *testing.T) {
		server := server.NewHTTP(service)
		res, err := server.ExecuteBatch(batch.NewRequest(t.Context(), nil))
		require.NoError(t, err)
		require.Nil(t, res.Metadata())
	})
}
