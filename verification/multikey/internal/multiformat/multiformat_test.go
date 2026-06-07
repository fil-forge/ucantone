package multiformat_test

import (
	"testing"

	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/verification/multikey/internal/multiformat"
	"github.com/stretchr/testify/require"
)

func TestTag(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		b := []byte{1, 2, 3}
		tb := multiformat.TagWith(1, b)
		utb := testutil.Must(multiformat.UntagWith(1, tb, 0))(t)
		require.EqualValues(t, b, utb)
	})

	t.Run("incorrect tag", func(t *testing.T) {
		b := []byte{1, 2, 3}
		tb := multiformat.TagWith(1, b)
		_, err := multiformat.UntagWith(2, tb, 0)
		require.Error(t, err)
		require.Equal(t, "expected multiformat with tag cidv2 [0x02] instead got cidv1 [0x01]", err.Error())
	})
}
