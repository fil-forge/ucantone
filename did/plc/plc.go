//go:build !codegen

package plc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"maps"
	"slices"

	did "github.com/fil-forge/ucantone/did"
)

const Method = "plc"

// IdentifierLength is the length in characters of the method-specific
// identifier of a did:plc DID.
const IdentifierLength = 24

var base32LowerNoPad = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Parse parses a did:plc DID string, verifying the method is "plc" and the
// identifier is 24 characters of base32 (lowercase, no padding).
func Parse(str string) (did.DID, error) {
	d, err := did.Parse(str)
	if err != nil {
		return did.Undef, err
	}
	if err := did.ValidateMethod(d, Method); err != nil {
		return did.Undef, err
	}
	id := d.Identifier()
	if len(id) != IdentifierLength {
		return did.Undef, fmt.Errorf("identifier must be %d characters, got %d", IdentifierLength, len(id))
	}
	if _, err := base32LowerNoPad.DecodeString(id); err != nil {
		return did.Undef, fmt.Errorf("identifier is not base32 (lowercase, no padding): %w", err)
	}
	return d, nil
}

func New(signer Signer, options ...OperationOption) (did.DID, *SignedOperation, error) {
	op, err := NewOperation(nil, options...)
	if err != nil {
		return did.Undef, nil, fmt.Errorf("creating genesis operation: %w", err)
	}
	signedOp, err := SignOperation(signer, op)
	if err != nil {
		return did.Undef, nil, fmt.Errorf("signing genesis operation: %w", err)
	}

	var signedOpBytes bytes.Buffer
	if err := signedOp.MarshalCBOR(&signedOpBytes); err != nil {
		return did.Undef, nil, fmt.Errorf("marshaling signed operation: %w", err)
	}

	digest := sha256.Sum256(signedOpBytes.Bytes())
	str := base32LowerNoPad.EncodeToString(digest[:])
	return did.New(Method, str[:IdentifierLength]), signedOp, nil
}

// SignOperation signs a PLC operation with the given signer and returns a
// SignedOperation.
func SignOperation(signer Signer, op *Operation) (*SignedOperation, error) {
	var sigPayload bytes.Buffer
	if err := op.MarshalCBOR(&sigPayload); err != nil {
		return nil, fmt.Errorf("marshaling operation: %w", err)
	}
	sig := signer.Sign(sigPayload.Bytes())
	var prev *string
	if op.Previous != nil {
		s := *op.Previous
		prev = &s
	}
	return &SignedOperation{
		Type:                op.Type,
		VerificationMethods: maps.Clone(op.VerificationMethods),
		RotationKeys:        slices.Clone(op.RotationKeys),
		AlsoKnownAs:         slices.Clone(op.AlsoKnownAs),
		Services:            maps.Clone(op.Services),
		Previous:            prev,
		Signature:           base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// VerifyOperationSignature verifies the signature of a SignedOperation using
// the provided Verifier.
func VerifyOperationSignature(verifier Verifier, signedOp *SignedOperation) error {
	var sigPayload bytes.Buffer
	if err := (&Operation{
		Type:                signedOp.Type,
		VerificationMethods: signedOp.VerificationMethods,
		RotationKeys:        signedOp.RotationKeys,
		AlsoKnownAs:         signedOp.AlsoKnownAs,
		Services:            signedOp.Services,
		Previous:            signedOp.Previous,
	}).MarshalCBOR(&sigPayload); err != nil {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(signedOp.Signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	if !verifier.Verify(sigPayload.Bytes(), sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

// SignTombstone signs a PLC tombstone with the given signer and returns a
// SignedTombstone.
func SignTombstone(signer Signer, op *Tombstone) (*SignedTombstone, error) {
	var sigPayload bytes.Buffer
	if err := op.MarshalCBOR(&sigPayload); err != nil {
		return nil, fmt.Errorf("marshaling tombstone: %w", err)
	}
	sig := signer.Sign(sigPayload.Bytes())
	return &SignedTombstone{
		Type:      op.Type,
		Previous:  op.Previous,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

func VerifyTombstoneSignature(verifier Verifier, signedOp *SignedTombstone) error {
	var sigPayload bytes.Buffer
	if err := (&Tombstone{
		Type:     signedOp.Type,
		Previous: signedOp.Previous,
	}).MarshalCBOR(&sigPayload); err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(signedOp.Signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}
	if !verifier.Verify(sigPayload.Bytes(), sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}
