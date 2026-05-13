package examples

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/examples/types"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/ucan/receipt"
)

// TestExtractTypedArgsFromInvocation demonstrates the bytes-native pattern
// for reading args, metadata, and receipt results — the most common shapes
// an ad-hoc consumer of a UCAN invocation will encounter.
//
// You receive a *ucan.Invocation* (or *ucan.Receipt*) from somewhere — over
// the wire, from a container, from disk — and you want to bind its fields
// to typed schemas. With the bytes accessors ([Invocation.ArgumentsBytes],
// [Invocation.MetadataBytes], [Receipt.Out]) this is one line of code per
// field: pass the bytes to your typed struct's cborgen-generated
// UnmarshalCBOR.
//
// Compare to the previous design, where args/meta were eagerly decoded
// into generic map[string]any structures during envelope unmarshal, and
// typed callers had to round-trip through a re-encode/re-decode helper
// (Rebind) to reach their typed struct. That intermediary is gone.
func TestExtractTypedArgsFromInvocation(t *testing.T) {
	// Setup: alice signs an invocation whose args use a typed cborgen
	// schema (types.EchoArguments). The args are marshalled to CBOR
	// bytes once and stored verbatim in the envelope.
	//
	// Metadata is spec'd as an untyped {String : Any} map — debug/audit
	// information that isn't semantically meaningful to the delegation
	// chain. Pass it as a Go map literal via WithMetadata.
	alice, err := ed25519.Generate()
	require.NoError(t, err)

	inv, err := invocation.Invoke(
		alice,
		alice.DID(), // subject
		"/example/echo",
		&types.EchoArguments{Message: "Hello, UCAN!"},
		invocation.WithMetadata(map[string]any{
			"trace_id":   "abc-123",
			"user_agent": "ucan-client/1.0",
		}),
	)
	require.NoError(t, err)

	// Wire round-trip: serialize for transport, deserialize on receipt.
	// The args and meta bytes survive untouched.
	encoded, err := invocation.Encode(inv)
	require.NoError(t, err)
	decoded, err := invocation.Decode(encoded)
	require.NoError(t, err)

	// === Typed args extraction ===
	//
	// Decode the args bytes directly into the typed struct. No Rebind,
	// no datamodel.Map intermediary, no library construct involved —
	// just the cborgen UnmarshalCBOR generated for your schema.
	var args types.EchoArguments
	require.NoError(t, args.UnmarshalCBOR(bytes.NewReader(decoded.ArgumentsBytes())))
	require.Equal(t, "Hello, UCAN!", args.Message)
	fmt.Printf("Decoded typed args: %+v\n", args)

	// The args CBOR bytes round-trip verbatim — the exact bytes alice
	// signed over are still in the envelope, byte-for-byte.
	var reMarshaled bytes.Buffer
	require.NoError(t, args.MarshalCBOR(&reMarshaled))
	require.Equal(t, reMarshaled.Bytes(), decoded.ArgumentsBytes(),
		"args bytes must be byte-identical across the wire round-trip")

	// === Metadata extraction ===
	//
	// Metadata is unstructured per the spec, so most consumers want a
	// generic map view. Decode the meta bytes into a datamodel.Map (a
	// map[string]any with cborgen methods).
	//
	// If you have a known metadata schema, you can decode into a typed
	// struct exactly the same way as args — same one-line pattern.
	var meta datamodel.Map
	require.NoError(t, meta.UnmarshalCBOR(bytes.NewReader(decoded.MetadataBytes())))
	require.Equal(t, "abc-123", meta["trace_id"])
	require.Equal(t, "ucan-client/1.0", meta["user_agent"])
	fmt.Printf("Decoded metadata: %+v\n", meta)

	// === Receipt round-trip — successful execution ===
	//
	// alice (acting as executor for this single-party demo) issues a
	// receipt attesting to a successful execution. The result is a
	// typed cborgen value — same schema treatment as args.
	okRcpt, err := receipt.IssueOK(
		alice,
		decoded.Task().Link(),
		&types.EchoArguments{Message: "echoed back!"},
	)
	require.NoError(t, err)

	okEncoded, err := receipt.Encode(okRcpt)
	require.NoError(t, err)
	okDecoded, err := receipt.Decode(okEncoded)
	require.NoError(t, err)

	// === Receipt round-trip — failed execution ===
	//
	// IssueErr is symmetric to IssueOK: typed cborgen value in, raw bytes
	// stored in the Err branch of the receipt's Out. The consumer-side
	// decode pattern is identical — only the populated branch differs.
	errRcpt, err := receipt.IssueErr(
		alice,
		decoded.Task().Link(),
		&edm.ErrorModel{ErrorName: "EchoFailure", Message: "executor went home early"},
	)
	require.NoError(t, err)

	errEncoded, err := receipt.Encode(errRcpt)
	require.NoError(t, err)
	errDecoded, err := receipt.Decode(errEncoded)
	require.NoError(t, err)

	// === Typed receipt result extraction ===
	//
	// Receipt.Out returns a result.Result[[]byte, []byte]. Dispatch with
	// IsOK and unpack to the (ok, err) pair. Both branches decode using
	// the same one-line pattern as args/meta — only the typed schema and
	// the populated branch differ.
	out := okDecoded.Out()
	require.True(t, out.IsOK())
	okBytes, _ := out.Unpack()
	var ok types.EchoArguments
	require.NoError(t, ok.UnmarshalCBOR(bytes.NewReader(okBytes)))
	require.Equal(t, "echoed back!", ok.Message)
	fmt.Printf("Decoded typed OK result: %+v\n", ok)

	failOut := errDecoded.Out()
	require.True(t, failOut.IsErr())
	_, errBytes := failOut.Unpack()
	var fail edm.ErrorModel
	require.NoError(t, fail.UnmarshalCBOR(bytes.NewReader(errBytes)))
	require.Equal(t, "EchoFailure", fail.ErrorName)
	require.Equal(t, "executor went home early", fail.Message)
	fmt.Printf("Decoded typed ERR result: %+v\n", fail)

	// The same one-line pattern works across every field a UCAN consumer
	// reads — args, meta, and either branch of a receipt's Out:
	//
	//   var args MyArgs
	//   args.UnmarshalCBOR(bytes.NewReader(inv.ArgumentsBytes()))
	//
	//   var meta MyMeta                                      // or datamodel.Map
	//   meta.UnmarshalCBOR(bytes.NewReader(inv.MetadataBytes()))
	//
	//   var ok MyResult
	//   ok.UnmarshalCBOR(bytes.NewReader(okBytes))           // OK branch
	//
	//   var fail MyError
	//   fail.UnmarshalCBOR(bytes.NewReader(errBytes))        // Err branch
}
