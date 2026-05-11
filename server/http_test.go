package server_test

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/result"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestHTTPServer(t *testing.T) {
	service := testutil.RandomSigner(t)
	alice := testutil.RandomSigner(t)

	t.Run("invocation execution round trip", func(t *testing.T) {
		server := server.NewHTTP(service, server.WithReceiptTimestamps(true))

		var messages []ipld.Any
		server.Handle(testutil.ConsoleLogCapability, func(req execution.Request, res execution.Response) error {
			msg := testutil.ArgsMap(t, req.Invocation())["message"]
			t.Log(msg)
			messages = append(messages, msg)
			return res.SetSuccess(datamodel.Map{})
		})
		server.Handle(testutil.TestEchoCapability, func(req execution.Request, res execution.Response) error {
			return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
		})

		logInv, err := testutil.ConsoleLogCapability.Invoke(
			alice,
			alice,
			datamodel.Map{"message": "Hello, World!"},
			invocation.WithAudience(service),
		)
		require.NoError(t, err)

		ct := container.New(container.WithInvocations(logInv))

		r, w := io.Pipe()
		go func() {
			err := ct.MarshalCBOR(w)
			w.CloseWithError(err)
		}()

		req := http.Request{Header: http.Header{}, Body: r}
		req.Header.Set("Content-Type", dagcbor.ContentType)

		resp, err := server.RoundTrip(&req)
		require.NoError(t, err)

		ctResp := container.Container{}
		err = ctResp.UnmarshalCBOR(resp.Body)
		require.NoError(t, err)

		require.Len(t, ctResp.Receipts(), 1)

		_, x := result.Unwrap(ctResp.Receipts()[0].Out())
		require.Nil(t, x)

		require.Len(t, messages, 1)
		require.Equal(t, "Hello, World!", messages[0])

		echoInv, err := testutil.TestEchoCapability.Invoke(
			alice,
			alice,
			datamodel.Map{"message": "echo!"},
			invocation.WithAudience(service),
		)
		require.NoError(t, err)

		ct = container.New(container.WithInvocations(echoInv))

		r, w = io.Pipe()
		go func() {
			err := ct.MarshalCBOR(w)
			w.CloseWithError(err)
		}()

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

		o, x := result.Unwrap(rcpt.Out())
		require.NotNil(t, o)
		require.Nil(t, x)
		t.Log(o)

		require.Len(t, messages, 1) // should not have changed
		require.Equal(t, "echo!", testutil.ResultMap(t, o)["message"])
	})
}
