package x25519_test

import (
	"strings"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/x25519"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	k, err := x25519.Generate()
	require.NoError(t, err)
	require.Len(t, k.Raw(), x25519.KeySize)
	require.Len(t, k.Public().Raw(), x25519.KeySize)

	// Two independent keypairs differ.
	k2, err := x25519.Generate()
	require.NoError(t, err)
	require.NotEqual(t, k.Raw(), k2.Raw())
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	k, err := x25519.Generate()
	require.NoError(t, err)

	t.Run("tagged bytes carry the x25519-priv code", func(t *testing.T) {
		b := k.Bytes()
		// 2-byte varint for 0x1302 + 32 raw bytes.
		require.Len(t, b, 34)

		decoded, err := x25519.Decode(b)
		require.NoError(t, err)
		require.Equal(t, k.Raw(), decoded.Raw())
	})

	t.Run("FromRaw", func(t *testing.T) {
		decoded, err := x25519.FromRaw(k.Raw())
		require.NoError(t, err)
		require.Equal(t, k.Bytes(), decoded.Bytes())
	})

	t.Run("Parse(String())", func(t *testing.T) {
		decoded, err := x25519.Parse(k.String())
		require.NoError(t, err)
		require.Equal(t, k.Raw(), decoded.Raw())
	})

	t.Run("Decode rejects the wrong key type", func(t *testing.T) {
		// An ed25519 private key is multiformat-tagged with a different code.
		signer, err := ed25519.Generate()
		require.NoError(t, err)
		_, err = x25519.Decode(signer.Bytes())
		require.Error(t, err)
	})

	t.Run("FromRaw rejects the wrong length", func(t *testing.T) {
		_, err := x25519.FromRaw([]byte{1, 2, 3})
		require.Error(t, err)
	})
}

func TestPublicKeyRoundTrip(t *testing.T) {
	k, err := x25519.Generate()
	require.NoError(t, err)
	pub := k.Public()

	t.Run("tagged bytes carry the x25519-pub code", func(t *testing.T) {
		b := pub.Bytes()
		require.Len(t, b, 34)

		decoded, err := x25519.DecodePublic(b)
		require.NoError(t, err)
		require.Equal(t, pub.Raw(), decoded.Raw())
	})

	t.Run("PublicFromRaw", func(t *testing.T) {
		decoded, err := x25519.PublicFromRaw(pub.Raw())
		require.NoError(t, err)
		require.Equal(t, pub.Bytes(), decoded.Bytes())
	})

	t.Run("ParsePublic(String())", func(t *testing.T) {
		decoded, err := x25519.ParsePublic(pub.String())
		require.NoError(t, err)
		require.Equal(t, pub.Raw(), decoded.Raw())
	})

	t.Run("DecodePublic rejects the wrong key type", func(t *testing.T) {
		// Tagged private bytes have the x25519-priv code, not x25519-pub.
		_, err := x25519.DecodePublic(k.Bytes())
		require.Error(t, err)
	})
}

func TestKeyDID(t *testing.T) {
	k, err := x25519.Generate()
	require.NoError(t, err)

	d := k.KeyDID()
	require.Equal(t, "key", d.Method())
	// X25519 did:key identifiers (x25519-pub, base58btc) begin "z6LS".
	require.True(t, strings.HasPrefix(d.String(), "did:key:z6LS"),
		"unexpected did:key prefix: %s", d.String())

	t.Run("ParsePublicKeyDID round trips", func(t *testing.T) {
		pub, err := x25519.ParsePublicKeyDID(d)
		require.NoError(t, err)
		require.Equal(t, k.Public().Raw(), pub.Raw())
	})

	t.Run("ParsePublicKeyDID rejects a non-key DID", func(t *testing.T) {
		_, err := x25519.ParsePublicKeyDID(did.New("plc", "abc123"))
		require.Error(t, err)
	})

	t.Run("ParsePublicKeyDID rejects an ed25519 did:key", func(t *testing.T) {
		signer, err := ed25519.Generate()
		require.NoError(t, err)
		_, err = x25519.ParsePublicKeyDID(signer.KeyDID())
		require.Error(t, err)
	})
}

func TestECDH(t *testing.T) {
	alice, err := x25519.Generate()
	require.NoError(t, err)
	bob, err := x25519.Generate()
	require.NoError(t, err)

	t.Run("both parties derive the same shared secret", func(t *testing.T) {
		ab, err := alice.ECDH(bob.Public())
		require.NoError(t, err)
		ba, err := bob.ECDH(alice.Public())
		require.NoError(t, err)
		require.NotEmpty(t, ab)
		require.Equal(t, ab, ba)
	})

	t.Run("a public key recovered from its DID agrees too", func(t *testing.T) {
		bobPub, err := x25519.ParsePublicKeyDID(bob.KeyDID())
		require.NoError(t, err)
		viaDID, err := alice.ECDH(bobPub)
		require.NoError(t, err)
		direct, err := alice.ECDH(bob.Public())
		require.NoError(t, err)
		require.Equal(t, direct, viaDID)
	})

	t.Run("returns an error for a nil peer instead of panicking", func(t *testing.T) {
		_, err := alice.ECDH(nil)
		require.Error(t, err)
		// A zero-value public key (nil underlying key) is also rejected.
		_, err = alice.ECDH(&x25519.PublicKey{})
		require.Error(t, err)
	})
}
