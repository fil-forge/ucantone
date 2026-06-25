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

		d, signedOp, err := plc.New(signer)
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

		d1, _, err := plc.New(signer)
		require.NoError(t, err)
		d2, _, err := plc.New(signer)
		require.NoError(t, err)

		require.Equal(t, d1, d2)
	})

	t.Run("produces distinct DIDs for distinct signers", func(t *testing.T) {
		d1, _, err := plc.New(testutil.RandomMultikeySigner(t))
		require.NoError(t, err)
		d2, _, err := plc.New(testutil.RandomMultikeySigner(t))
		require.NoError(t, err)

		require.NotEqual(t, d1, d2)
	})

	t.Run("options flow through to the signed operation", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		rotationKey := testutil.RandomDID(t)

		_, signedOp, err := plc.New(signer, plc.WithRotationKeys([]did.DID{rotationKey}))
		require.NoError(t, err)
		require.Equal(t, []did.DID{rotationKey}, signedOp.RotationKeys)
	})
}

func TestSignOperation(t *testing.T) {
	t.Run("signs the CBOR-encoded operation and copies all fields", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		vm := testutil.RandomDID(t)
		rk := testutil.RandomDID(t)

		op := plc.NewOperation(
			nil,
			plc.WithVerificationMethods(map[string]did.DID{"atproto": vm}),
			plc.WithRotationKeys([]did.DID{rk}),
			plc.WithAlsoKnownAs([]string{"at://alice.example"}),
		)

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
		op := plc.NewOperation(
			nil,
			plc.WithVerificationMethods(map[string]did.DID{"atproto": testutil.RandomDID(t)}),
			plc.WithRotationKeys([]did.DID{testutil.RandomDID(t)}),
			plc.WithAlsoKnownAs([]string{"at://alice.example"}),
		)
		signed, err := plc.SignOperation(signer, op)
		require.NoError(t, err)

		require.NoError(t, plc.VerifyOperationSignature(signer.Verifier(), signed))
	})

	t.Run("accepts a genesis operation produced by New", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		_, signed, err := plc.New(signer, plc.WithRotationKeys([]did.DID{testutil.RandomDID(t)}))
		require.NoError(t, err)

		require.NoError(t, plc.VerifyOperationSignature(signer.Verifier(), signed))
	})

	t.Run("rejects a signature from a different key", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		other := testutil.RandomMultikeySigner(t)
		signed, err := plc.SignOperation(signer, plc.NewOperation(nil))
		require.NoError(t, err)

		err = plc.VerifyOperationSignature(other.Verifier(), signed)
		require.ErrorContains(t, err, "invalid signature")
	})

	t.Run("rejects a tampered payload", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		signed, err := plc.SignOperation(signer, plc.NewOperation(nil))
		require.NoError(t, err)

		// Mutate a field after signing: the recomputed payload no longer matches.
		signed.AlsoKnownAs = append(signed.AlsoKnownAs, "at://mallory.example")

		err = plc.VerifyOperationSignature(signer.Verifier(), signed)
		require.ErrorContains(t, err, "invalid signature")
	})

	t.Run("errors on a malformed signature encoding", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		signed, err := plc.SignOperation(signer, plc.NewOperation(nil))
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
