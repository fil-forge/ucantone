package secp256k1_test

import (
	"crypto"
	"crypto/sha256"
	"testing"

	secp256k1 "github.com/fil-forge/ucantone/principal/secp256k1"
	"github.com/stretchr/testify/require"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

func TestGenerateEncodeDecode(t *testing.T) {
	s0, err := secp256k1.Generate()
	require.NoError(t, err)

	t.Log(s0.DID().String())

	s1, err := secp256k1.Decode(s0.Bytes())
	require.NoError(t, err)

	t.Log(s1.DID().String())
	require.Equal(t, s0.DID(), s1.DID(), "public key mismatch")
}

func TestGenerateFormatParse(t *testing.T) {
	s0, err := secp256k1.Generate()
	require.NoError(t, err)

	t.Log(s0.DID().String())

	str := secp256k1.Format(s0)
	t.Log(str)

	s1, err := secp256k1.Parse(str)
	require.NoError(t, err)

	t.Log(s1.DID().String())
	require.Equal(t, s0.DID(), s1.DID(), "public key mismatch")
}

func TestVerify(t *testing.T) {
	s, err := secp256k1.Generate()
	require.NoError(t, err)

	msg := []byte("testy")
	sig := s.Sign(msg)

	res := s.Verifier().Verify(msg, sig)
	require.True(t, res)
}

func TestSignerRaw(t *testing.T) {
	s, err := secp256k1.Generate()
	require.NoError(t, err)

	msg := []byte{1, 2, 3}
	hash := sha256.New()
	hash.Write(msg)
	raw := s.Raw()

	sk, err := secec.NewPrivateKey(raw)
	require.NoError(t, err)

	sig, err := sk.Sign(
		secec.RFC6979SHA256(),
		hash.Sum(nil),
		&secec.ECDSAOptions{
			Encoding:   secec.EncodingCompact,
			SelfVerify: false,
			Hash:       crypto.SHA256,
		},
	)
	require.NoError(t, err)

	require.Equal(t, s.Sign(msg), sig)
}

func TestFromRaw(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		priv, err := secec.GenerateKey()
		require.NoError(t, err)

		s, err := secp256k1.FromRaw(priv.Bytes())
		require.NoError(t, err)

		require.Equal(t, priv.Bytes(), s.Raw())
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := secp256k1.FromRaw([]byte{})
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid length")
	})
}
