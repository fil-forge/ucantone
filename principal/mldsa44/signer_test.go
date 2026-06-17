package mldsa44_test

import (
	"testing"

	"filippo.io/mldsa"
	md "github.com/fil-forge/ucantone/principal/mldsa44"
	"github.com/stretchr/testify/require"
)

func TestGenerateEncodeDecode(t *testing.T) {
	s0, err := md.Generate()
	require.NoError(t, err)

	t.Log(s0.DID().String())

	s1, err := md.Decode(s0.Bytes())
	require.NoError(t, err)

	t.Log(s1.DID().String())
	require.Equal(t, s0.DID(), s1.DID(), "public key mismatch")
}

func TestGenerateFormatParse(t *testing.T) {
	s0, err := md.Generate()
	require.NoError(t, err)

	t.Log(s0.DID().String())

	str := md.Format(s0)
	t.Log(str)

	s1, err := md.Parse(str)
	require.NoError(t, err)

	t.Log(s1.DID().String())
	require.Equal(t, s0.DID(), s1.DID(), "public key mismatch")
}

func TestVerify(t *testing.T) {
	s0, err := md.Generate()
	require.NoError(t, err)

	msg := []byte("testy")
	sig := s0.Sign(msg)

	res := s0.Verifier().Verify(msg, sig)
	require.True(t, res)
}

func TestSignerRaw(t *testing.T) {
	s, err := md.Generate()
	require.NoError(t, err)

	msg := []byte{1, 2, 3}
	raw := s.Raw()
	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), raw)
	require.NoError(t, err)
	sig, err := sk.SignDeterministic(msg, nil)
	require.NoError(t, err)

	require.Equal(t, s.Sign(msg), sig)
}

func TestFromRaw(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
		require.NoError(t, err)

		s, err := md.FromRaw(sk.Bytes())
		require.NoError(t, err)

		require.Equal(t, sk.Bytes(), s.Raw())
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := md.FromRaw([]byte{})
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid length")
	})
}
