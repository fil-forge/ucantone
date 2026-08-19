package secp256k1_test

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/stretchr/testify/require"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

func TestGenerateEncodeDecode(t *testing.T) {
	s0, err := secp256k1.Generate()
	require.NoError(t, err)

	t.Log(multikey.FormatVerifier(s0.Verifier().(multikey.Verifier)))

	s1, err := secp256k1.Decode(s0.Bytes())
	require.NoError(t, err)

	t.Log(multikey.FormatVerifier(s1.Verifier().(multikey.Verifier)))
	require.Equal(t, s0.Bytes(), s1.Bytes(), "private key mismatch")
	require.Equal(t, s0.Verifier(), s1.Verifier(), "public key mismatch")
}

func TestGenerateFormatParse(t *testing.T) {
	s0, err := secp256k1.Generate()
	require.NoError(t, err)

	t.Log(multikey.FormatVerifier(s0.Verifier().(multikey.Verifier)))

	str := secp256k1.Format(s0)
	t.Log(str)

	s1, err := secp256k1.Parse(str)
	require.NoError(t, err)

	t.Log(multikey.FormatVerifier(s1.Verifier().(multikey.Verifier)))
	require.Equal(t, s0.Verifier(), s1.Verifier(), "public key mismatch")
}

func TestSignerString(t *testing.T) {
	s, err := secp256k1.Generate()
	require.NoError(t, err)

	require.Equal(t, s.KeyDID().String(), fmt.Sprint(s))
}

func TestSignerStringZeroValue(t *testing.T) {
	require.Equal(t, "<invalid secp256k1 signer>", fmt.Sprint(secp256k1.Signer{}))
}

func TestSignerFormatDoesNotLeakKey(t *testing.T) {
	s, err := secp256k1.Generate()
	require.NoError(t, err)

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		t.Run(verb, func(t *testing.T) {
			out := fmt.Sprintf(verb, s)
			require.NotContains(t, out, fmt.Sprintf("%x", s.Raw()))
			require.NotContains(t, out, fmt.Sprintf("%d", s.Raw()))
		})
	}
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
