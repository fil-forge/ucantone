package examples

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/fil-forge/ucantone/examples/types"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

// TestExtractTypedArgsFromInvocation demonstrates the bytes-native args
// access pattern — the most common shape an ad-hoc consumer of a UCAN
// invocation will encounter.
//
// You receive a *ucan.Invocation* from somewhere — over the wire, from a
// container, from disk — and you want to bind the args field to a typed
// struct that matches the schema for the invocation's command. With
// [Invocation.ArgumentsBytes] this is one line of code: pass the bytes
// to your typed struct's cborgen-generated UnmarshalCBOR.
//
// Compare to the previous design, where args were eagerly decoded into
// a generic map[string]any during envelope unmarshal, and typed callers
// had to round-trip through a re-encode/re-decode helper (Rebind) to
// reach their typed struct. That intermediary is gone.
func TestExtractTypedArgsFromInvocation(t *testing.T) {
	// Setup: alice signs an invocation whose args use a typed cborgen
	// schema (types.EchoArguments). The args are marshalled to CBOR
	// bytes once and stored verbatim in the envelope.
	alice, err := ed25519.Generate()
	require.NoError(t, err)

	inv, err := invocation.Invoke(
		alice,
		alice, // subject
		"/example/echo",
		&types.EchoArguments{Message: "Hello, UCAN!"},
	)
	require.NoError(t, err)

	// Wire round-trip: serialize for transport, deserialize on receipt.
	// The args bytes survive untouched.
	encoded, err := invocation.Encode(inv)
	require.NoError(t, err)
	decoded, err := invocation.Decode(encoded)
	require.NoError(t, err)

	// === The win ===
	//
	// Decode the args bytes directly into the typed struct. No Rebind,
	// no datamodel.Map intermediary, no library construct involved —
	// just the cborgen UnmarshalCBOR generated for your schema.
	var args types.EchoArguments
	err = args.UnmarshalCBOR(bytes.NewReader(decoded.ArgumentsBytes()))
	require.NoError(t, err)

	require.Equal(t, "Hello, UCAN!", args.Message)
	fmt.Printf("Decoded typed args: %+v\n", args)

	// The CBOR bytes round-trip verbatim — the exact bytes alice signed
	// over are still in the envelope, byte-for-byte. This is what makes
	// signature verification spec-faithful by construction.
	var reMarshaled bytes.Buffer
	require.NoError(t, args.MarshalCBOR(&reMarshaled))
	require.Equal(t, reMarshaled.Bytes(), decoded.ArgumentsBytes(),
		"args bytes must be byte-identical across the wire round-trip")
}

// TestVerifySignatureOperatesOnLiteralBytes shows that signature
// verification reads the literal signed-payload bytes preserved on
// decode, not a reconstruction from typed fields. This means a
// signature verifies regardless of whether our typed re-encoder
// happens to produce byte-identical output to the sender's encoder
// — which matches the UCAN spec's envelope description ("signature
// is over the SigPayload field").
func TestVerifySignatureOperatesOnLiteralBytes(t *testing.T) {
	alice, err := ed25519.Generate()
	require.NoError(t, err)

	inv, err := invocation.Invoke(
		alice,
		alice,
		"/example/echo",
		&types.EchoArguments{Message: "signed and sealed"},
	)
	require.NoError(t, err)

	// Wire round-trip.
	encoded, err := invocation.Encode(inv)
	require.NoError(t, err)
	decoded, err := invocation.Decode(encoded)
	require.NoError(t, err)

	// SignedBytes is the canonical CBOR of the SigPayload — exactly
	// what alice signed over. Verification compares the signature
	// against these bytes directly.
	require.NotEmpty(t, decoded.SignedBytes())

	ok, err := invocation.VerifySignature(decoded, alice.Verifier())
	require.NoError(t, err)
	require.True(t, ok)
}
