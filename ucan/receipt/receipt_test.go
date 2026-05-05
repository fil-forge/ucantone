package receipt_test

import (
	"testing"

	"github.com/fil-forge/ucantone/result"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/receipt"
	"github.com/stretchr/testify/require"
)

func TestIssue(t *testing.T) {
	t.Run("minimal", func(t *testing.T) {
		executor := testutil.RandomSigner(t)
		ran := testutil.RandomCID(t)
		out := result.OK[int64, any](42)

		initial, err := receipt.Issue(executor, ran, out)
		require.NoError(t, err)

		encoded, err := receipt.Encode(initial)
		require.NoError(t, err)

		decoded, err := receipt.Decode(encoded)
		require.NoError(t, err)

		require.Equal(t, executor.DID(), decoded.Issuer().DID())
		require.Equal(t, ran, decoded.Ran())

		o, x := result.Unwrap(decoded.Out())
		require.Nil(t, x)
		require.Equal(t, int64(42), o)
	})
}
