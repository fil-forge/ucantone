package container_test

import (
	"bytes"
	"io"
	"slices"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/container/datamodel"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/ucan/receipt"
	"github.com/stretchr/testify/require"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func TestContainer(t *testing.T) {
	codecs := []byte{
		container.Raw,
		container.Base64,
		container.Base64url,
		container.RawGzip,
		container.Base64Gzip,
		container.Base64urlGzip,
	}
	for _, code := range codecs {
		t.Run(container.FormatCodec(code)+" with invocation", func(t *testing.T) {
			issuer := testutil.RandomIssuer(t)
			subject := testutil.RandomDID(t)
			command := testutil.Must(command.Parse("/test/invoke"))(t)
			arguments := testutil.RandomArgs(t)

			inv, err := invocation.Invoke(issuer, subject, command, arguments)
			require.NoError(t, err)

			initial := container.New(container.WithInvocations(inv))

			bytes, err := container.Encode(code, initial)
			require.NoError(t, err)

			decoded, err := container.Decode(bytes)
			require.NoError(t, err)
			require.Len(t, decoded.Invocations(), 1)
		})
	}
}

func TestContainerDecodeWhitespaceTolerance(t *testing.T) {
	testCases := []struct {
		code     byte
		tolerate bool
	}{
		// Textual (base64) encodings may pick up surrounding whitespace, e.g. a
		// trailing newline when written to or read from a file.
		{container.Base64, true},
		{container.Base64url, true},
		{container.Base64Gzip, true},
		{container.Base64urlGzip, true},
		// Do not tolerate whitespace for binary encodings.
		{container.Raw, false},
		{container.RawGzip, false},
	}
	for _, tc := range testCases {
		t.Run(container.FormatCodec(tc.code), func(t *testing.T) {
			issuer := testutil.RandomIssuer(t)
			subject := testutil.RandomDID(t)
			cmd := testutil.Must(command.Parse("/test/invoke"))(t)
			arguments := testutil.RandomArgs(t)

			inv, err := invocation.Invoke(issuer, subject, cmd, arguments)
			require.NoError(t, err)

			encoded, err := container.Encode(tc.code, container.New(container.WithInvocations(inv)))
			require.NoError(t, err)

			// Wrap with leading and trailing whitespace of various kinds.
			padded := append([]byte("\n\t  "), encoded...)
			padded = append(padded, []byte("  \n")...)

			decoded, err := container.Decode(padded)
			if tc.tolerate {
				require.NoError(t, err)
				require.Len(t, decoded.Invocations(), 1)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestContainerDeduplicates(t *testing.T) {
	issuer := testutil.RandomIssuer(t)
	audience := testutil.RandomDID(t)
	subject := testutil.RandomDID(t)
	cmd := testutil.Must(command.Parse("/test/invoke"))(t)
	arguments := testutil.RandomArgs(t)

	dlg, err := delegation.Delegate(issuer, audience, did.Undef, cmd)
	require.NoError(t, err)

	inv, err := invocation.Invoke(issuer, subject, cmd, arguments)
	require.NoError(t, err)

	out := cbg.CborInt(1)
	rcpt, err := receipt.IssueOK(issuer, inv.Link(), &out)
	require.NoError(t, err)

	ct := container.New(
		container.WithDelegations(dlg, dlg),
		container.WithDelegations(dlg),
		container.WithInvocations(inv, inv),
		container.WithInvocations(inv),
		container.WithReceipts(rcpt, rcpt),
		container.WithReceipts(rcpt),
	)

	require.Len(t, ct.Delegations(), 1)
	require.Len(t, ct.Invocations(), 1)
	require.Len(t, ct.Receipts(), 1)
}

func TestDecodeTransport(t *testing.T) {
	codecs := []byte{
		container.Raw,
		container.Base64,
		container.Base64url,
		container.RawGzip,
		container.Base64Gzip,
		container.Base64urlGzip,
	}
	for _, code := range codecs {
		t.Run(container.FormatCodec(code), func(t *testing.T) {
			issuer := testutil.RandomIssuer(t)
			audience := testutil.RandomDID(t)
			subject := testutil.RandomDID(t)
			cmd := testutil.Must(command.Parse("/test/invoke"))(t)
			arguments := testutil.RandomArgs(t)

			inv, err := invocation.Invoke(issuer, subject, cmd, arguments)
			require.NoError(t, err)

			dlg, err := delegation.Delegate(issuer, audience, did.Undef, cmd)
			require.NoError(t, err)

			out := cbg.CborInt(1)
			rcpt, err := receipt.IssueOK(issuer, inv.Task().Link(), &out)
			require.NoError(t, err)

			encoded, err := container.Encode(code, container.New(
				container.WithInvocations(inv),
				container.WithDelegations(dlg),
				container.WithReceipts(rcpt),
			))
			require.NoError(t, err)

			codec, raw, err := container.DecodeTransport(encoded)
			require.NoError(t, err)
			require.Equal(t, code, codec)

			model := datamodel.ContainerModel{}
			require.NoError(t, model.UnmarshalCBOR(bytes.NewReader(raw)))

			// Encode sorts the entries bytewise for determinism.
			expected := [][]byte{
				testutil.Must(invocation.Encode(inv))(t),
				testutil.Must(delegation.Encode(dlg))(t),
				testutil.Must(receipt.Encode(rcpt))(t),
			}
			slices.SortFunc(expected, bytes.Compare)
			require.Equal(t, expected, model.Ctn1)
		})
	}
}

func TestDecodeTransportKeepsUndecodableEntries(t *testing.T) {
	issuer := testutil.RandomIssuer(t)
	subject := testutil.RandomDID(t)
	cmd := testutil.Must(command.Parse("/test/invoke"))(t)
	arguments := testutil.RandomArgs(t)

	inv, err := invocation.Invoke(issuer, subject, cmd, arguments)
	require.NoError(t, err)

	entries := [][]byte{[]byte("not a ucan"), testutil.Must(invocation.Encode(inv))(t)}

	var buf bytes.Buffer
	require.NoError(t, (&datamodel.ContainerModel{Ctn1: entries}).MarshalCBOR(&buf))
	encoded := append([]byte{container.Raw}, buf.Bytes()...)

	t.Run("DecodeTransport returns every entry", func(t *testing.T) {
		_, raw, err := container.DecodeTransport(encoded)
		require.NoError(t, err)

		model := datamodel.ContainerModel{}
		require.NoError(t, model.UnmarshalCBOR(bytes.NewReader(raw)))
		require.Equal(t, entries, model.Ctn1)
	})

	t.Run("Decode drops the undecodable entry", func(t *testing.T) {
		decoded, err := container.Decode(encoded)
		require.NoError(t, err)
		require.Len(t, decoded.Invocations(), 1)
	})
}

func TestDecodeTransportErrors(t *testing.T) {
	testCases := map[string]struct {
		input           []byte
		expectedMessage string
	}{
		"empty input":           {[]byte{}, "empty container bytes"},
		"whitespace-only input": {[]byte("  \n"), "empty container bytes"},
		"unknown codec byte":    {[]byte{0x41, 0x00}, "unknown codec: 0x41"},
	}
	for desc, tc := range testCases {
		t.Run(desc, func(t *testing.T) {
			_, _, err := container.DecodeTransport(tc.input)
			require.EqualError(t, err, tc.expectedMessage)
		})
	}
}

func TestContainerMaxTokens(t *testing.T) {
	t.Run("encodes and decodes exactly MaxTokens", func(t *testing.T) {
		model := datamodel.ContainerModel{Ctn1: make([][]byte, container.MaxTokens)}

		var cborBuf bytes.Buffer
		require.NoError(t, model.MarshalCBOR(&cborBuf))
		var jsonBuf bytes.Buffer
		require.NoError(t, model.MarshalDagJSON(&jsonBuf))

		var decoded datamodel.ContainerModel
		require.NoError(t, decoded.UnmarshalCBOR(&cborBuf))
		require.Len(t, decoded.Ctn1, container.MaxTokens)
	})

	t.Run("refuses to encode MaxTokens+1", func(t *testing.T) {
		model := datamodel.ContainerModel{Ctn1: make([][]byte, container.MaxTokens+1)}
		require.Error(t, model.MarshalCBOR(io.Discard))
		require.Error(t, model.MarshalDagJSON(io.Discard))
	})

	t.Run("refuses to decode MaxTokens+1", func(t *testing.T) {
		// {"ctn-v1": [ ...MaxTokens+1 items ]}: only the headers are needed,
		// the decoder rejects the array length before reading any element.
		var buf bytes.Buffer
		cw := cbg.NewCborWriter(&buf)
		require.NoError(t, cw.WriteMajorTypeHeader(cbg.MajMap, 1))
		require.NoError(t, cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len(datamodel.Tag))))
		_, err := cw.WriteString(datamodel.Tag)
		require.NoError(t, err)
		require.NoError(t, cw.WriteMajorTypeHeader(cbg.MajArray, container.MaxTokens+1))

		var decoded datamodel.ContainerModel
		err = decoded.UnmarshalCBOR(&buf)
		require.ErrorContains(t, err, "array too large")
	})
}
