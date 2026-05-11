package invocation_test

import (
	"bytes"
	"testing"

	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/principal/secp256k1"
	"github.com/fil-forge/ucantone/testutil"
	hdm "github.com/fil-forge/ucantone/testutil/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestInvoke(t *testing.T) {
	t.Run("minimal", func(t *testing.T) {
		issuer := testutil.RandomSigner(t)
		subject := testutil.RandomDID(t)
		command := testutil.Must(command.Parse("/test/invoke"))(t)
		arguments := datamodel.Map{}
		then := ucan.Now()

		initial, err := invocation.Invoke(issuer, subject, command, arguments)
		require.NoError(t, err)

		encoded, err := invocation.Encode(initial)
		require.NoError(t, err)

		decoded, err := invocation.Decode(encoded)
		require.NoError(t, err)

		require.Equal(t, issuer.DID(), decoded.Issuer().DID())
		require.Equal(t, subject, decoded.Subject())
		require.Equal(t, command, decoded.Command())
		require.Nil(t, decoded.Audience())
		require.NotEmpty(t, decoded.Nonce())
		require.GreaterOrEqual(t, *decoded.Expiration(), then)
	})

	t.Run("bad command", func(t *testing.T) {
		issuer := testutil.RandomSigner(t)
		subject := testutil.RandomDID(t)
		arguments := datamodel.Map{}

		_, err := invocation.Invoke(issuer, subject, "testinvoke", arguments)
		require.Error(t, err)
		require.ErrorIs(t, err, command.ErrRequiresLeadingSlash)
	})

	t.Run("no nonce", func(t *testing.T) {
		issuer := testutil.RandomSigner(t)
		subject := testutil.RandomDID(t)
		command := testutil.Must(command.Parse("/test/invoke"))(t)
		arguments := datamodel.Map{}

		initial, err := invocation.Invoke(issuer, subject, command, arguments, invocation.WithNoNonce())
		require.NoError(t, err)

		encoded, err := invocation.Encode(initial)
		require.NoError(t, err)

		decoded, err := invocation.Decode(encoded)
		require.NoError(t, err)

		require.NoError(t, err)
		require.Nil(t, decoded.Nonce())
	})

	t.Run("custom nonce", func(t *testing.T) {
		issuer := testutil.RandomSigner(t)
		subject := testutil.RandomDID(t)
		command := testutil.Must(command.Parse("/test/invoke"))(t)
		arguments := datamodel.Map{}
		nonce := []byte{1, 2, 3}

		initial, err := invocation.Invoke(issuer, subject, command, arguments, invocation.WithNonce(nonce))
		require.NoError(t, err)

		encoded, err := invocation.Encode(initial)
		require.NoError(t, err)

		decoded, err := invocation.Decode(encoded)
		require.NoError(t, err)

		require.Equal(t, nonce, decoded.Nonce())
	})

	t.Run("no expiration", func(t *testing.T) {
		issuer := testutil.RandomSigner(t)
		subject := testutil.RandomDID(t)
		command := testutil.Must(command.Parse("/test/invoke"))(t)
		arguments := datamodel.Map{}

		initial, err := invocation.Invoke(issuer, subject, command, arguments, invocation.WithNoExpiration())
		require.NoError(t, err)

		encoded, err := invocation.Encode(initial)
		require.NoError(t, err)

		decoded, err := invocation.Decode(encoded)
		require.NoError(t, err)

		require.NoError(t, err)
		require.Nil(t, decoded.Expiration())
	})

	t.Run("custom expiration", func(t *testing.T) {
		issuer := testutil.RandomSigner(t)
		subject := testutil.RandomDID(t)
		command := testutil.Must(command.Parse("/test/invoke"))(t)
		arguments := datamodel.Map{}
		expiration := ucan.Now() + 138

		initial, err := invocation.Invoke(issuer, subject, command, arguments, invocation.WithExpiration(expiration))
		require.NoError(t, err)

		encoded, err := invocation.Encode(initial)
		require.NoError(t, err)

		decoded, err := invocation.Decode(encoded)
		require.NoError(t, err)

		require.Equal(t, expiration, *decoded.Expiration())
	})

	t.Run("custom audience", func(t *testing.T) {
		issuer := testutil.RandomSigner(t)
		subject := testutil.RandomDID(t)
		command := testutil.Must(command.Parse("/test/invoke"))(t)
		arguments := datamodel.Map{}
		audience := testutil.RandomDID(t)

		initial, err := invocation.Invoke(issuer, subject, command, arguments, invocation.WithAudience(audience))
		require.NoError(t, err)

		encoded, err := invocation.Encode(initial)
		require.NoError(t, err)

		decoded, err := invocation.Decode(encoded)
		require.NoError(t, err)

		require.Equal(t, &audience, decoded.Audience())
	})

	t.Run("custom auguments", func(t *testing.T) {
		issuer := testutil.RandomSigner(t)
		subject := testutil.RandomDID(t)
		command := testutil.Must(command.Parse("/test/invoke"))(t)
		arguments := testutil.RandomArgs(t)

		initial, err := invocation.Invoke(issuer, subject, command, arguments)
		require.NoError(t, err)

		encoded, err := invocation.Encode(initial)
		require.NoError(t, err)

		decoded, err := invocation.Decode(encoded)
		require.NoError(t, err)

		// Decode args bytes directly into the typed cborgen struct.
		var decodedArgs hdm.TestArgs
		require.NoError(t, decodedArgs.UnmarshalCBOR(bytes.NewReader(decoded.ArgumentsBytes())))
		require.Equal(t, arguments, &decodedArgs)
	})

	t.Run("secp256k1", func(t *testing.T) {
		issuer := testutil.Must(secp256k1.Generate())(t)
		subject := testutil.RandomDID(t)
		command := testutil.Must(command.Parse("/test/invoke"))(t)
		arguments := datamodel.Map{}

		inv, err := invocation.Invoke(issuer, subject, command, arguments)
		require.NoError(t, err)

		encoded, err := invocation.Encode(inv)
		require.NoError(t, err)

		decoded, err := invocation.Decode(encoded)
		require.NoError(t, err)

		ok, err := invocation.VerifySignature(decoded, issuer.Verifier())
		require.NoError(t, err)
		require.True(t, ok)
	})
}

// TestArgsBytesRoundTrip is the byte-faithfulness test that proves the
// verification-correctness story: the envelope's args bytes round-trip
// verbatim through decode and re-encode. Without datamodel.Raw this test
// would fail any time the decoded map's key ordering differs from our
// canonical re-encode (which is the latent risk Raw eliminates).
func TestArgsBytesRoundTrip(t *testing.T) {
	issuer := testutil.RandomSigner(t)
	subject := testutil.RandomDID(t)
	command := testutil.Must(command.Parse("/test/invoke"))(t)
	arguments := testutil.RandomArgs(t)

	inv, err := invocation.Invoke(issuer, subject, command, arguments)
	require.NoError(t, err)

	encoded, err := invocation.Encode(inv)
	require.NoError(t, err)

	decoded, err := invocation.Decode(encoded)
	require.NoError(t, err)

	// 1. Envelope-level: re-encoding a decoded invocation must produce
	//    byte-identical envelope bytes.
	reencoded, err := invocation.Encode(decoded)
	require.NoError(t, err)
	require.Equal(t, encoded, reencoded, "envelope bytes must round-trip verbatim")

	// 2. Args-level: the raw CBOR args bytes survive decode unchanged.
	var argsBuf bytes.Buffer
	require.NoError(t, arguments.MarshalCBOR(&argsBuf))
	require.Equal(t, argsBuf.Bytes(), decoded.ArgumentsBytes(),
		"args bytes must round-trip verbatim")

	// 3. Signature verification on the decoded invocation must succeed
	//    (this exercises the Raw-bytes path through VerifySignature).
	ok, err := invocation.VerifySignature(decoded, issuer.Verifier())
	require.NoError(t, err)
	require.True(t, ok, "signature must verify after decode/re-encode")
}
