package eddsa_test

import (
	"testing"

	"github.com/fil-forge/ucantone/varsig/algorithm/eddsa"
	"github.com/multiformats/go-multicodec"
	"github.com/stretchr/testify/require"
)

func TestEddsa(t *testing.T) {
	t.Run("round trips", func(t *testing.T) {
		alg := eddsa.New(multicodec.Ed25519Pub, multicodec.Sha2_512)
		require.Equal(t, multicodec.Ed25519Pub, alg.Curve())
		require.Equal(t, multicodec.Sha2_512, alg.HashAlgorithm())

		bytes, err := alg.Encode()
		require.NoError(t, err)

		decodedAlg, n, err := eddsa.Decode(bytes)
		decodedEddsaAlg, ok := decodedAlg.(eddsa.Algorithm)
		require.True(t, ok)

		require.NoError(t, err)
		require.Equal(t, len(bytes), n)
		require.Equal(t, alg.Curve(), decodedEddsaAlg.Curve())
		require.Equal(t, alg.HashAlgorithm(), decodedEddsaAlg.HashAlgorithm())
	})

	t.Run("fails with invalid curve", func(t *testing.T) {
		alg := eddsa.New(multicodec.Tcp, multicodec.Sha2_512)
		bytes, err := alg.Encode()
		require.NoError(t, err)

		_, _, err = eddsa.Decode(bytes)
		require.ErrorContains(t, err, "invalid curve code: 0x06 (tcp, 'multiaddr'), expected a multicodec with 'key' tag")
	})

	t.Run("fails with invalid hash algorithm", func(t *testing.T) {
		alg := eddsa.New(multicodec.Ed25519Pub, multicodec.Tcp)
		bytes, err := alg.Encode()
		require.NoError(t, err)

		_, _, err = eddsa.Decode(bytes)
		require.ErrorContains(t, err, "invalid hash algorithm code: 0x06 (tcp, 'multiaddr'), expected a multicodec with 'multihash' tag")
	})
}
