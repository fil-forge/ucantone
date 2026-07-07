package mldsa_test

import (
	"testing"

	"github.com/fil-forge/ucantone/varsig"
	"github.com/fil-forge/ucantone/varsig/algorithm/mldsa"
	"github.com/stretchr/testify/require"
)

func TestMldsa(t *testing.T) {
	t.Run("round trips", func(t *testing.T) {
		alg := mldsa.New()
		require.Equal(t, uint64(mldsa.Code), alg.Code())
		require.Equal(t, []uint64{mldsa.Code}, alg.Segments())

		bytes, err := alg.Encode()
		require.NoError(t, err)

		decodedAlg, n, err := mldsa.Decode(bytes)
		require.NoError(t, err)
		require.Equal(t, len(bytes), n)

		_, ok := decodedAlg.(mldsa.Algorithm)
		require.True(t, ok)
	})

	t.Run("fails with wrong code", func(t *testing.T) {
		_, _, err := mldsa.Decode([]byte{0x00})
		require.ErrorContains(t, err, "signature code is not ML-DSA-44")
	})

	t.Run("registered with the varsig scheme registry", func(t *testing.T) {
		bytes, err := mldsa.MLDSA44.Encode()
		require.NoError(t, err)

		alg, n, err := varsig.AlgorithmScheme(mldsa.Code).Decode(bytes)
		require.NoError(t, err)
		require.Equal(t, len(bytes), n)

		_, ok := alg.(mldsa.Algorithm)
		require.True(t, ok)
	})
}
