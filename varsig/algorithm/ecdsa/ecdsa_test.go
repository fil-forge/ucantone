package ecdsa_test

import (
	"testing"

	"github.com/fil-forge/ucantone/varsig/algorithm/ecdsa"
	"github.com/multiformats/go-multicodec"
	"github.com/stretchr/testify/require"
)

func TestEcdsa(t *testing.T) {
	t.Run("round trips", func(t *testing.T) {
		alg := ecdsa.New(multicodec.Ed25519Pub, multicodec.Sha2_512)
		require.Equal(t, multicodec.Ed25519Pub, alg.Curve())
		require.Equal(t, multicodec.Sha2_512, alg.HashAlgorithm())

		bytes, err := alg.Encode()
		require.NoError(t, err)

		decodedAlg, n, err := ecdsa.Decode(bytes)
		decodedEcdsaAlg, ok := decodedAlg.(ecdsa.Algorithm)
		require.True(t, ok)

		require.NoError(t, err)
		require.Equal(t, len(bytes), n)
		require.Equal(t, alg.Curve(), decodedEcdsaAlg.Curve())
		require.Equal(t, alg.HashAlgorithm(), decodedEcdsaAlg.HashAlgorithm())
	})

	t.Run("fails with invalid curve", func(t *testing.T) {
		alg := ecdsa.New(multicodec.Tcp, multicodec.Sha2_512)
		bytes, err := alg.Encode()
		require.NoError(t, err)

		_, _, err = ecdsa.Decode(bytes)
		require.ErrorContains(t, err, "invalid curve code: 0x06 (tcp, 'multiaddr'), expected a multicodec with 'key' tag")
	})

	t.Run("fails with invalid hash algorithm", func(t *testing.T) {
		alg := ecdsa.New(multicodec.Ed25519Pub, multicodec.Tcp)
		bytes, err := alg.Encode()
		require.NoError(t, err)

		_, _, err = ecdsa.Decode(bytes)
		require.ErrorContains(t, err, "invalid hash algorithm code: 0x06 (tcp, 'multiaddr'), expected a multicodec with 'multihash' tag")
	})
}
