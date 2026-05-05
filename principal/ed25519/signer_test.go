package ed25519_test

import (
	"crypto/ed25519"
	"testing"

	ed "github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/stretchr/testify/require"
)

func TestGenerateEncodeDecode(t *testing.T) {
	s0, err := ed.Generate()
	require.NoError(t, err)

	t.Log(s0.DID().String())

	s1, err := ed.Decode(s0.Bytes())
	require.NoError(t, err)

	t.Log(s1.DID().String())
	require.Equal(t, s0.DID(), s1.DID(), "public key mismatch")
}

func TestGenerateFormatParse(t *testing.T) {
	s0, err := ed.Generate()
	require.NoError(t, err)

	t.Log(s0.DID().String())

	str := ed.Format(s0)
	t.Log(str)

	s1, err := ed.Parse(str)
	require.NoError(t, err)

	t.Log(s1.DID().String())
	require.Equal(t, s0.DID(), s1.DID(), "public key mismatch")
}

func TestVerify(t *testing.T) {
	s0, err := ed.Generate()
	require.NoError(t, err)

	msg := []byte("testy")
	sig := s0.Sign(msg)

	res := s0.Verifier().Verify(msg, sig)
	require.True(t, res)
}

func TestSignerRaw(t *testing.T) {
	s, err := ed.Generate()
	require.NoError(t, err)

	msg := []byte{1, 2, 3}
	raw := s.Raw()
	sk := ed25519.NewKeyFromSeed(raw)
	sig := ed25519.Sign(sk, msg)

	require.Equal(t, s.Sign(msg), sig)
}

func TestFromRaw(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		s, err := ed.FromRaw(priv[:ed25519.SeedSize])
		require.NoError(t, err)

		require.Equal(t, []byte(priv[:ed25519.SeedSize]), s.Raw())
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := ed.FromRaw([]byte{})
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid length")
	})
}
