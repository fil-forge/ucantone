package plc_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("generates a valid did:plc DID and genesis operation", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)

		d, signedOp, err := plc.New(signer, plc.WithRotationKeys(testutil.RandomDID(t)))
		require.NoError(t, err)

		require.True(t, strings.HasPrefix(d.String(), "did:plc:"), "expected did:plc: prefix, got %s", d.String())
		id := strings.TrimPrefix(d.String(), "did:plc:")
		require.Len(t, id, 24)

		require.NotNil(t, signedOp)
		require.Equal(t, plc.OperationType, signedOp.Type)
		require.NotEmpty(t, signedOp.Signature)
		require.Nil(t, signedOp.Previous, "genesis operation must have no previous")
	})

	t.Run("is deterministic for the same signer and options", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		rotationKey := testutil.RandomDID(t)

		d1, _, err := plc.New(signer, plc.WithRotationKeys(rotationKey))
		require.NoError(t, err)
		d2, _, err := plc.New(signer, plc.WithRotationKeys(rotationKey))
		require.NoError(t, err)

		require.Equal(t, d1, d2)
	})

	t.Run("produces distinct DIDs for distinct signers", func(t *testing.T) {
		d1, _, err := plc.New(testutil.RandomMultikeySigner(t), plc.WithRotationKeys(testutil.RandomDID(t)))
		require.NoError(t, err)
		d2, _, err := plc.New(testutil.RandomMultikeySigner(t), plc.WithRotationKeys(testutil.RandomDID(t)))
		require.NoError(t, err)

		require.NotEqual(t, d1, d2)
	})

	t.Run("options flow through to the signed operation", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		rotationKey := testutil.RandomDID(t)

		_, signedOp, err := plc.New(signer, plc.WithRotationKeys(rotationKey))
		require.NoError(t, err)
		require.Equal(t, []did.DID{rotationKey}, signedOp.RotationKeys)
	})
}

func TestParse(t *testing.T) {
	t.Run("accepts a DID produced by New", func(t *testing.T) {
		d, _, err := plc.New(testutil.RandomMultikeySigner(t), plc.WithRotationKeys(testutil.RandomDID(t)))
		require.NoError(t, err)

		parsed, err := plc.Parse(d.String())
		require.NoError(t, err)
		require.Equal(t, d, parsed)
	})

	t.Run("accepts a well-known did:plc", func(t *testing.T) {
		d, err := plc.Parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz")
		require.NoError(t, err)
		require.Equal(t, plc.Method, d.Method())
	})

	t.Run("rejects a missing did prefix", func(t *testing.T) {
		_, err := plc.Parse("plc:ewvi7nxzyoun6zhxrhs64oiz")
		require.Error(t, err)
	})

	t.Run("rejects a non-plc method", func(t *testing.T) {
		_, err := plc.Parse("did:web:example.com")
		var umErr did.UnsupportedMethodError
		require.ErrorAs(t, err, &umErr)
	})

	t.Run("rejects an identifier that is too short", func(t *testing.T) {
		_, err := plc.Parse("did:plc:ewvi7nxzyoun6zhxrhs64oi")
		require.ErrorContains(t, err, "24 characters")
	})

	t.Run("rejects an identifier that is too long", func(t *testing.T) {
		_, err := plc.Parse("did:plc:ewvi7nxzyoun6zhxrhs64oizz")
		require.ErrorContains(t, err, "24 characters")
	})

	t.Run("rejects characters outside the base32 lower alphabet", func(t *testing.T) {
		for _, id := range []string{
			"EWVI7NXZYOUN6ZHXRHS64OIZ", // uppercase
			"ewvi7nxzyoun6zhxrhs64oi0", // digit outside 2-7
			"ewvi7nxzyoun6zhxrhs64oi=", // padding
		} {
			_, err := plc.Parse("did:plc:" + id)
			require.ErrorContains(t, err, "not base32", "identifier %q", id)
		}
	})
}

func TestSignOperation(t *testing.T) {
	t.Run("signs the CBOR-encoded operation and copies all fields", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		vm := testutil.RandomDID(t)
		rk := testutil.RandomDID(t)

		op, err := plc.NewOperation(
			nil,
			plc.WithVerificationMethods(map[string]did.DID{"atproto": vm}),
			plc.WithRotationKeys(rk),
			plc.WithAlsoKnownAs("at://alice.example"),
		)
		require.NoError(t, err)

		signed, err := plc.SignOperation(signer, op)
		require.NoError(t, err)

		// Fields copied verbatim.
		require.Equal(t, op.Type, signed.Type)
		require.Equal(t, op.VerificationMethods, signed.VerificationMethods)
		require.Equal(t, op.RotationKeys, signed.RotationKeys)
		require.Equal(t, op.AlsoKnownAs, signed.AlsoKnownAs)
		require.Equal(t, op.Services, signed.Services)
		require.Equal(t, op.Previous, signed.Previous)

		// Signature is RawURLEncoding base64 of signer.Sign(CBOR(op)).
		var payload bytes.Buffer
		require.NoError(t, op.MarshalCBOR(&payload))
		expectedSig := base64.RawURLEncoding.EncodeToString(signer.Sign(payload.Bytes()))
		require.Equal(t, expectedSig, signed.Signature)

		// Signature validates against the signer's verifier over the CBOR payload.
		sigBytes, err := base64.RawURLEncoding.DecodeString(signed.Signature)
		require.NoError(t, err)
		require.True(t, signer.Verifier().Verify(payload.Bytes(), sigBytes))
	})
}

func TestVerifyOperationSignature(t *testing.T) {
	t.Run("accepts a valid signature", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		op, err := plc.NewOperation(
			nil,
			plc.WithVerificationMethods(map[string]did.DID{"atproto": testutil.RandomDID(t)}),
			plc.WithRotationKeys(testutil.RandomDID(t)),
			plc.WithAlsoKnownAs("at://alice.example"),
		)
		require.NoError(t, err)
		signed, err := plc.SignOperation(signer, op)
		require.NoError(t, err)

		require.NoError(t, plc.VerifyOperationSignature(signer.Verifier(), signed))
	})

	t.Run("accepts a genesis operation produced by New", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		_, signed, err := plc.New(signer, plc.WithRotationKeys(testutil.RandomDID(t)))
		require.NoError(t, err)

		require.NoError(t, plc.VerifyOperationSignature(signer.Verifier(), signed))
	})

	t.Run("rejects a signature from a different key", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		other := testutil.RandomMultikeySigner(t)
		op, err := plc.NewOperation(nil, plc.WithRotationKeys(testutil.RandomDID(t)))
		require.NoError(t, err)
		signed, err := plc.SignOperation(signer, op)
		require.NoError(t, err)

		err = plc.VerifyOperationSignature(other.Verifier(), signed)
		require.ErrorContains(t, err, "invalid signature")
	})

	t.Run("rejects a tampered payload", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		op, err := plc.NewOperation(nil, plc.WithRotationKeys(testutil.RandomDID(t)))
		require.NoError(t, err)
		signed, err := plc.SignOperation(signer, op)
		require.NoError(t, err)

		// Mutate a field after signing: the recomputed payload no longer matches.
		signed.AlsoKnownAs = append(signed.AlsoKnownAs, "at://mallory.example")

		err = plc.VerifyOperationSignature(signer.Verifier(), signed)
		require.ErrorContains(t, err, "invalid signature")
	})

	t.Run("errors on a malformed signature encoding", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		op, err := plc.NewOperation(nil, plc.WithRotationKeys(testutil.RandomDID(t)))
		require.NoError(t, err)
		signed, err := plc.SignOperation(signer, op)
		require.NoError(t, err)
		signed.Signature = "!!!not base64"

		err = plc.VerifyOperationSignature(signer.Verifier(), signed)
		require.ErrorContains(t, err, "decoding signature")
	})
}

func TestSignTombstone(t *testing.T) {
	t.Run("signs the CBOR-encoded tombstone and copies fields", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		prev := testutil.RandomCID(t)

		tomb := plc.NewTombstone(prev)
		signed, err := plc.SignTombstone(signer, tomb)
		require.NoError(t, err)

		require.Equal(t, tomb.Type, signed.Type)
		require.Equal(t, tomb.Previous, signed.Previous)

		var payload bytes.Buffer
		require.NoError(t, tomb.MarshalCBOR(&payload))
		expectedSig := base64.RawURLEncoding.EncodeToString(signer.Sign(payload.Bytes()))
		require.Equal(t, expectedSig, signed.Signature)

		sigBytes, err := base64.RawURLEncoding.DecodeString(signed.Signature)
		require.NoError(t, err)
		require.True(t, signer.Verifier().Verify(payload.Bytes(), sigBytes))
	})
}

func TestVerifyTombstoneSignature(t *testing.T) {
	t.Run("accepts a valid signature", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		signed, err := plc.SignTombstone(signer, plc.NewTombstone(testutil.RandomCID(t)))
		require.NoError(t, err)

		require.NoError(t, plc.VerifyTombstoneSignature(signer.Verifier(), signed))
	})

	t.Run("rejects a signature from a different key", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		other := testutil.RandomMultikeySigner(t)
		signed, err := plc.SignTombstone(signer, plc.NewTombstone(testutil.RandomCID(t)))
		require.NoError(t, err)

		err = plc.VerifyTombstoneSignature(other.Verifier(), signed)
		require.ErrorContains(t, err, "invalid signature")
	})

	t.Run("rejects a tampered payload", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		signed, err := plc.SignTombstone(signer, plc.NewTombstone(testutil.RandomCID(t)))
		require.NoError(t, err)

		// Mutate the previous link after signing.
		signed.Previous = testutil.RandomCID(t).String()

		err = plc.VerifyTombstoneSignature(signer.Verifier(), signed)
		require.ErrorContains(t, err, "invalid signature")
	})

	t.Run("errors on a malformed signature encoding", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		signed, err := plc.SignTombstone(signer, plc.NewTombstone(testutil.RandomCID(t)))
		require.NoError(t, err)
		signed.Signature = "!!!"

		err = plc.VerifyTombstoneSignature(signer.Verifier(), signed)
		require.ErrorContains(t, err, "decoding signature")
	})
}
