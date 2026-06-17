package verifier_test

import (
	"testing"

	"filippo.io/mldsa"
	"github.com/fil-forge/ucantone/principal/mldsa44"
	"github.com/fil-forge/ucantone/principal/mldsa44/verifier"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	s, err := mldsa44.Generate()
	require.NoError(t, err)

	str := s.DID().String()
	v, err := verifier.Parse(str)
	require.NoError(t, err)
	require.Equal(t, str, v.DID().String())
}

func TestDecode(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
		require.NoError(t, err)

		v, err := verifier.FromRaw(sk.PublicKey().Bytes())
		require.NoError(t, err)

		v2, err := verifier.Decode(v.Bytes())
		require.NoError(t, err)
		require.Equal(t, v, v2)
	})
}

func TestFromRaw(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
		require.NoError(t, err)

		pub := sk.PublicKey().Bytes()
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
