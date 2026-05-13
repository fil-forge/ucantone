package receipt_test

import (
	"bytes"
	"testing"

	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/receipt"
	"github.com/stretchr/testify/require"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func TestIssue(t *testing.T) {
	t.Run("minimal", func(t *testing.T) {
		executor := testutil.RandomSigner(t)
		ran := testutil.RandomCID(t)

		ok := cbg.CborInt(42)
		initial, err := receipt.IssueOK(executor, ran, &ok)
		require.NoError(t, err)

		encoded, err := receipt.Encode(initial)
		require.NoError(t, err)

		decoded, err := receipt.Decode(encoded)
		require.NoError(t, err)

		require.Equal(t, executor.DID(), decoded.Issuer())
		require.Equal(t, ran, decoded.Ran())

		okBytes, errBytes := decoded.Out().Unpack()
		require.Nil(t, errBytes)

		var got cbg.CborInt
		require.NoError(t, got.UnmarshalCBOR(bytes.NewReader(okBytes)))
		require.Equal(t, cbg.CborInt(42), got)
	})
}
