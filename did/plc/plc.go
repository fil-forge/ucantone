//go:build !codegen

package plc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"fmt"

	did "github.com/fil-forge/ucantone/did"
)

const Method = "plc"

func New(signer Signer, options ...OperationOption) (did.DID, *SignedOperation, error) {
	op := NewOperation(nil, options...)
	signedOp, err := SignOperation(signer, op)
	if err != nil {
		return did.Undef, nil, fmt.Errorf("failed to sign genesis operation: %w", err)
	}

	var signedOpBytes bytes.Buffer
	if err := signedOp.MarshalCBOR(&signedOpBytes); err != nil {
		return did.Undef, nil, err
	}

	digest := sha256.Sum256(signedOpBytes.Bytes())
	str := base32.StdEncoding.EncodeToString(digest[:])
	return did.New(Method, str[:24]), signedOp, nil
}

// SignOperation signs a PLC operation with the given signer and returns a
// SignedOperation.
func SignOperation(signer Signer, op *Operation) (*SignedOperation, error) {
	var sigPayload bytes.Buffer
	if err := op.MarshalCBOR(&sigPayload); err != nil {
		return nil, err
	}
	sig := signer.Sign(sigPayload.Bytes())
	return &SignedOperation{
		Type:                op.Type,
		VerificationMethods: op.VerificationMethods,
		RotationKeys:        op.RotationKeys,
		AlsoKnownAs:         op.AlsoKnownAs,
		Services:            op.Services,
		Previous:            op.Previous,
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
		return nil, err
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
