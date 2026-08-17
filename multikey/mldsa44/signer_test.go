package mldsa44_test

import (
	"testing"

	"filippo.io/mldsa"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/mldsa44"
	"github.com/stretchr/testify/require"
)

func TestGenerateEncodeDecode(t *testing.T) {
	s0, err := mldsa44.Generate()
	require.NoError(t, err)

	t.Log(multikey.FormatVerifier(s0.Verifier().(multikey.Verifier)))

	s1, err := mldsa44.Decode(s0.Bytes())
	require.NoError(t, err)

	t.Log(multikey.FormatVerifier(s1.Verifier().(multikey.Verifier)))
	require.Equal(t, s0, s1, "private key mismatch")
	require.Equal(t, s0.Verifier(), s1.Verifier(), "public key mismatch")
}

func TestGenerateFormatParse(t *testing.T) {
	s0, err := mldsa44.Generate()
	require.NoError(t, err)

	t.Log(multikey.FormatVerifier(s0.Verifier().(multikey.Verifier)))

	str := mldsa44.Format(s0)
	t.Log(str)

	s1, err := mldsa44.Parse(str)
	require.NoError(t, err)

	t.Log(multikey.FormatVerifier(s1.Verifier().(multikey.Verifier)))
	require.Equal(t, s0.Verifier(), s1.Verifier(), "public key mismatch")
}

func TestVerify(t *testing.T) {
	s, err := mldsa44.Generate()
	require.NoError(t, err)

	msg := []byte("testy")
	sig := s.Sign(msg)

	res := s.Verifier().Verify(msg, sig)
	require.True(t, res)
}

// TestSignerRaw asserts that signing is deterministic: reconstructing the
// private key from the signer's raw seed and signing the same message yields the
// exact same signature bytes.
func TestSignerRaw(t *testing.T) {
	s, err := mldsa44.Generate()
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

		s, err := mldsa44.FromRaw(sk.Bytes())
		require.NoError(t, err)

		require.Equal(t, sk.Bytes(), s.Raw())
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := mldsa44.FromRaw([]byte{})
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid length")
	})
}

// TestGenerateIssuer covers the full issuer round-trip a caller sees: generate
// an issuer, sign with it, and verify the signature through the issuer's own
// verifier.
func TestGenerateIssuer(t *testing.T) {
	issuer, err := mldsa44.GenerateIssuer()
	require.NoError(t, err)
	require.Equal(t, issuer.KeyDID(), issuer.DID())

	msg := []byte("testy")
	sig := issuer.Sign(msg)
	require.True(t, issuer.Verifier().Verify(msg, sig))
}

// TestParseKeyDIDRoundTrip covers the `did:key` string -> [multikey.Parse] ->
// verifier -> verify path, confirming the verifier package's Decoder is
// registered and that a signature made by the signer verifies against the parsed
// verifier.
func TestParseKeyDIDRoundTrip(t *testing.T) {
	s, err := mldsa44.Generate()
	require.NoError(t, err)

	msg := []byte("post-quantum")
	sig := s.Sign(msg)

	keyDID := s.KeyDID()
	v, err := multikey.Parse(keyDID.Identifier())
	require.NoError(t, err)

	require.Equal(t, keyDID, v.KeyDID())
	require.True(t, v.Verify(msg, sig))
}
