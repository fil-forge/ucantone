package container_test

import (
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
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
