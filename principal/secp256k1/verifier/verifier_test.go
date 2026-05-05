package verifier_test

import (
	"testing"

	"github.com/fil-forge/ucantone/principal/secp256k1/verifier"
	"github.com/stretchr/testify/require"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

func TestParse(t *testing.T) {
	str := "did:key:zQ3shokFvN6Ggnq5j6G76527464y7n7y767y767y767y767y7"
	v, err := verifier.Parse(str)
	require.NoError(t, err)
	require.Equal(t, str, v.DID().String())
}

func TestFromRaw(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		priv, err := secec.GenerateKey()
		require.NoError(t, err)

		pub := priv.PublicKey().CompressedBytes()
		v, err := verifier.FromRaw(pub)
		require.NoError(t, err)

		require.Equal(t, pub, v.Raw())
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := verifier.FromRaw([]byte{})
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid length")
	})
}
