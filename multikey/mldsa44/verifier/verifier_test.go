package verifier_test

import (
	"testing"

	"filippo.io/mldsa"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/mldsa44"
	"github.com/fil-forge/ucantone/multikey/mldsa44/verifier"
	"github.com/stretchr/testify/require"
)

// TestParseKeyDID round-trips a `did:key` string through [verifier.ParseKeyDID].
// ML-DSA-44 public keys are 1312 bytes, so rather than hardcode a DID we derive
// one from a freshly generated signer.
func TestParseKeyDID(t *testing.T) {
	s, err := mldsa44.Generate()
	require.NoError(t, err)

	str := s.KeyDID().String()
	v, err := verifier.ParseKeyDID(str)
	require.NoError(t, err)
	require.Equal(t, str, v.KeyDID().String())
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

// TestParseAndVerify covers the `did:key` -> [multikey.Parse] -> verify path,
// confirming the package's Decoder is registered with the multikey registry via
// its init and that a signature verifies against the parsed verifier.
func TestParseAndVerify(t *testing.T) {
	s, err := mldsa44.Generate()
	require.NoError(t, err)

	msg := []byte("testy")
	sig := s.Sign(msg)

	v, err := multikey.Parse(s.KeyDID().Identifier())
	require.NoError(t, err)
	require.True(t, v.Verify(msg, sig))
}
