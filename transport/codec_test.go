package transport_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
	"testing/iotest"

	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/transport"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/ucan/receipt"
	"github.com/stretchr/testify/require"
)

func TestHTTPInboundCodec(t *testing.T) {
	alice := testutil.RandomSigner(t)
	bob := testutil.RandomSigner(t)
	service := testutil.RandomSigner(t)

	cmd, err := command.Parse("/console/log")
	require.NoError(t, err)

	del, err := delegation.Delegate(alice, bob, alice, cmd)
	require.NoError(t, err)

	args := datamodel.Map{"message": "test"}
	inv, err := invocation.Invoke(bob, alice, cmd, args, invocation.WithAudience(service))
	require.NoError(t, err)

	rec, err := receipt.IssueOK(
		service,
		inv.Task().Link(),
		datamodel.Map{},
	)
	require.NoError(t, err)

	t.Run("decode", func(t *testing.T) {
		ct := container.New(container.WithDelegations(del), container.WithInvocations(inv))

		ctBytes, err := container.Encode(container.Raw, ct)
		require.NoError(t, err)

		r := http.Request{
			Header: http.Header{},
			Body:   io.NopCloser(bytes.NewReader(ctBytes[1:])),
		}
		r.Header.Set("Content-Type", dagcbor.ContentType)

		dct, err := transport.DefaultHTTPInboundCodec.Decode(&r)
		require.NoError(t, err)

		require.Len(t, dct.Invocations(), 1)
		require.Len(t, dct.Delegations(), 1)
		require.Equal(t, inv.Link(), dct.Invocations()[0].Link())
		require.Equal(t, del.Link(), dct.Delegations()[0].Link())
	})

	t.Run("decode invalid content type", func(t *testing.T) {
		ct := container.New(container.WithDelegations(del), container.WithInvocations(inv))

		ctBytes, err := container.Encode(container.Raw, ct)
		require.NoError(t, err)

		r := http.Request{
			Header: http.Header{},
			Body:   io.NopCloser(bytes.NewReader(ctBytes[1:])),
		}
		r.Header.Set("Content-Type", "application/json")

		_, err = transport.DefaultHTTPInboundCodec.Decode(&r)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid content type")
	})

	t.Run("decode body read error", func(t *testing.T) {
		r := http.Request{
			Header: http.Header{},
			Body:   io.NopCloser(iotest.ErrReader(errors.New("read error"))),
		}
		r.Header.Set("Content-Type", dagcbor.ContentType)

		_, err = transport.DefaultHTTPInboundCodec.Decode(&r)
		require.Error(t, err)
		require.ErrorContains(t, err, "unmarshaling request")
	})

	t.Run("decode invalid body", func(t *testing.T) {
		r := http.Request{
			Header: http.Header{},
			Body:   io.NopCloser(bytes.NewReader([]byte{})),
		}
		r.Header.Set("Content-Type", dagcbor.ContentType)

		_, err = transport.DefaultHTTPInboundCodec.Decode(&r)
		require.Error(t, err)
		require.ErrorContains(t, err, "unmarshaling request")
	})

	t.Run("encode", func(t *testing.T) {
		ct := container.New(container.WithReceipts(rec))

		r, err := transport.DefaultHTTPInboundCodec.Encode(ct)
		require.NoError(t, err)

		dct := container.Container{}
		err = dct.UnmarshalCBOR(r.Body)
		require.NoError(t, err)

		require.Len(t, dct.Receipts(), 1)
		require.Equal(t, rec.Link(), dct.Receipts()[0].Link())
	})
}

func TestHTTPOutboundCodec(t *testing.T) {
	alice := testutil.RandomSigner(t)
	bob := testutil.RandomSigner(t)
	service := testutil.RandomSigner(t)

	cmd, err := command.Parse("/console/log")
	require.NoError(t, err)

	del, err := delegation.Delegate(alice, bob, alice, cmd)
	require.NoError(t, err)

	args := datamodel.Map{"message": "test"}
	inv, err := invocation.Invoke(bob, alice, cmd, args, invocation.WithAudience(service))
	require.NoError(t, err)

	rec, err := receipt.IssueOK(
		service,
		inv.Task().Link(),
		datamodel.Map{},
	)
	require.NoError(t, err)

	t.Run("encode", func(t *testing.T) {
		ct := container.New(container.WithDelegations(del), container.WithInvocations(inv))

		r, err := transport.DefaultHTTPOutboundCodec.Encode(ct)
		require.NoError(t, err)

		dct := container.Container{}
		err = dct.UnmarshalCBOR(r.Body)
		require.NoError(t, err)

		require.Len(t, dct.Invocations(), 1)
		require.Len(t, dct.Delegations(), 1)
		require.Equal(t, inv.Link(), dct.Invocations()[0].Link())
		require.Equal(t, del.Link(), dct.Delegations()[0].Link())
	})

	t.Run("decode", func(t *testing.T) {
		ct := container.New(container.WithReceipts(rec))

		ctBytes, err := container.Encode(container.Raw, ct)
		require.NoError(t, err)

		r := http.Response{
			Header: http.Header{},
			Body:   io.NopCloser(bytes.NewReader(ctBytes[1:])),
		}
		r.Header.Set("Content-Type", dagcbor.ContentType)

		dct, err := transport.DefaultHTTPOutboundCodec.Decode(&r)
		require.NoError(t, err)

		require.Len(t, dct.Receipts(), 1)
		require.Equal(t, rec.Link(), dct.Receipts()[0].Link())
	})

	t.Run("decode invalid content type", func(t *testing.T) {
		ct := container.New(container.WithReceipts(rec))

		ctBytes, err := container.Encode(container.Raw, ct)
		require.NoError(t, err)

		r := http.Response{
			Header: http.Header{},
			Body:   io.NopCloser(bytes.NewReader(ctBytes)),
		}
		r.Header.Set("Content-Type", "application/json")

		_, err = transport.DefaultHTTPOutboundCodec.Decode(&r)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid content type")
	})

	t.Run("decode body read error", func(t *testing.T) {
		r := http.Response{
			Header: http.Header{},
			Body:   io.NopCloser(iotest.ErrReader(errors.New("read error"))),
		}
		r.Header.Set("Content-Type", dagcbor.ContentType)

		_, err = transport.DefaultHTTPOutboundCodec.Decode(&r)
		require.Error(t, err)
		require.ErrorContains(t, err, "unmarshaling response")
	})

	t.Run("decode invalid body", func(t *testing.T) {
		r := http.Response{
			Header: http.Header{},
			Body:   io.NopCloser(bytes.NewReader([]byte{})),
		}
		r.Header.Set("Content-Type", dagcbor.ContentType)

		_, err = transport.DefaultHTTPOutboundCodec.Decode(&r)
		require.Error(t, err)
		require.ErrorContains(t, err, "unmarshaling response")
	})
}
