package verifier_test

import (
	"testing"

	"github.com/fil-forge/ucantone/verification/multikey/secp256k1/verifier"
	"github.com/stretchr/testify/require"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

func TestParse(t *testing.T) {
	str := "did:key:zQ3shokFvN6Ggnq5j6G76527464y7n7y767y767y767y767y7"
	v, err := verifier.ParseKeyDID(str)
	require.NoError(t, err)
	require.Equal(t, str, v.KeyDID().String())
}

func TestDecode(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		priv, err := secec.GenerateKey()
		require.NoError(t, err)

		v, err := verifier.FromRaw(priv.PublicKey().CompressedBytes())
		require.NoError(t, err)

		v2, err := verifier.Decode(v.Bytes())
		require.NoError(t, err)
		require.Equal(t, v, v2)
	})
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
