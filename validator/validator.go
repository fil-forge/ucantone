// Package validator provides [validator.Validator], which can validate a
// [ucan.Invocation].
package validator

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/token"
	verrs "github.com/fil-forge/ucantone/validator/errors"
	"github.com/fil-forge/ucantone/varsig/algorithm/ecdsa"
	"github.com/fil-forge/ucantone/varsig/algorithm/eddsa"
	"github.com/fil-forge/ucantone/varsig/algorithm/nonstandard"
	"github.com/fil-forge/ucantone/verification"
	_ "github.com/fil-forge/ucantone/verification/multikey"
	_ "github.com/fil-forge/ucantone/verification/multikey/ed25519/verifier"
	_ "github.com/fil-forge/ucantone/verification/multikey/secp256k1/verifier"
	"github.com/ipfs/go-cid"
)

// ValidateInvocation determines whether an [ucan.Invocation] is a valid request
// to execute a task. If an invocation is valid, its audience is expected to
// execute its task. If an invocation is invalid, its audience is expected to
// reject the request.
func ValidateInvocation(
	ctx context.Context,
	inv ucan.Invocation,
	options ...Option,
) error {
	cfg := makeCfg(options...)

	// To be valid, an invocation must be a valid token...
	err := ValidateToken(ctx, inv, withConfig(cfg))
	if err != nil {
		return err
	}

	// ...and have a valid proof chain...
	cap, err := capabilityFromProofChain(ctx, inv, cfg)
	if err != nil {
		return err
	}

	// ...and have the capability to perform its task under the proof chain.
	var mapArgs datamodel.Map
	err = mapArgs.UnmarshalCBOR(bytes.NewReader(inv.ArgumentsBytes()))
	if err != nil {
		return fmt.Errorf("decoding invocation arguments for capability check: %w", err)
	}
	err = cap.Allows(
		inv.Subject(),
		inv.Command(),
		mapArgs,
	)
	if err != nil {
		return err
	}

	return nil
}

// ValidateToken determines whether a [ucan.Token] is a valid UCAN token. To be
// valid, a token must have a valid signature from its issuer and be within its
// time bounds. An [ucan.Invocation] is a token, but has additional
// requirements. An invocation may be a valid token but still an invalid
// invocation, if its proof chain is insufficient.
func ValidateToken(
	ctx context.Context,
	tok ucan.Token,
	options ...Option,
) error {
	cfg := makeCfg(options...)

	// To be valid, a token must have a valid signature from its issuer...
	err := verifyTokenSignature(ctx, tok, cfg)
	if err != nil {
		return err
	}

	// ...and not be expired...
	err = ValidateNotExpired(tok, cfg.validationTime)
	if err != nil {
		return err
	}

	// ...and not be too early.
	if dlg, ok := tok.(ucan.Delegation); ok {
		// Currently, only delegations have a "not before" time bound in this
		// library. But the spec is unclear as to whether all tokens should have
		// them, so this check is left in this function for now.
		//
		// https://github.com/ucan-wg/invocation/issues/45
		err = ValidateNotTooEarly(dlg, cfg.validationTime)
		if err != nil {
			return err
		}
	}

	return nil
}

// verifyTokenSignature verifies the token was signed by the passed verifier.
func verifyTokenSignature(ctx context.Context, tok ucan.Token, cfg validationConfig) error {
	if tok.Signature().Header().SignatureAlgorithm().Code() == nonstandard.Code {
		return cfg.verifyNonStandardSignature(ctx, tok, cfg.metadata)
	}

	doc, err := cfg.didResolver.Resolve(ctx, tok.Issuer())
	if err != nil {
		return err
	}

	// Look at the correct verification relationship in the DID Document.
	var verRel *did.VerificationRelationship
	switch tok.(type) {
	case ucan.Invocation:
		verRel = doc.CapabilityInvocation
	case ucan.Delegation:
		verRel = doc.CapabilityDelegation
	default:
		return fmt.Errorf("unsupported token type: %T", tok)
	}

	// Determine the required type of verification method from the signature
	// algorithm code.
	var vmType string
	switch tok.Signature().Header().SignatureAlgorithm().Code() {
	case eddsa.Code, ecdsa.Code:
		vmType = "Multikey"
	default:
		return fmt.Errorf("unsupported Varsig signature algorithm code: 0x%02x", tok.Signature().Header().SignatureAlgorithm().Code())
	}

	// Find all verification methods in that relationship with the correct type,
	// and make a verifier for each one.
	var vs []ucan.Verifier
	for _, vm := range verRel.All() {
		if vm.Type == vmType {
			v, err := verification.DeriveVerifier(vm)
			if err != nil {
				return err
			}
			vs = append(vs, v)
		}
	}

	for _, v := range vs {
		if token.VerifySignature(tok, v) {
			return nil
		}
	}

	return verrs.NewInvalidSignatureError(tok, vs)
}

func capabilityFromProofChain(ctx context.Context, inv ucan.Invocation, cfg validationConfig) (Capability, error) {
	prfs := make([]ucan.Delegation, 0, len(inv.Proofs()))
	for _, p := range inv.Proofs() {
		prf, err := cfg.resolveProof(ctx, p)
		if err != nil {
			return Capability{}, err
		}
		prfs = append(prfs, prf)
	}

	currentAuthority := inv.Subject()
	currentCapability := NewCapability(inv.Subject())
	for i, prf := range prfs {
		if err := ValidateToken(ctx, prf, withConfig(cfg)); err != nil {
			return Capability{}, err
		}

		// The first proof must have a non-null subject (that is, may not be a
		// powerline delegation).
		//
		// https://github.com/ucan-wg/delegation#powerline
		if i == 0 && prf.Subject() == did.Undef {
			return Capability{}, verrs.NewInvalidClaimError("root delegation subject is null")
		}

		// Every proof's subject must match the invocation's subject, or be null
		// (a powerline delegation).
		if prf.Subject() != did.Undef && prf.Subject() != inv.Subject() {
			return Capability{}, verrs.NewSubjectAlignmentError(inv.Subject(), prf)
		}

		// Every proof's issuer must match the previous proof's audience (or the
		// invocation's subject, for the first proof).
		if prf.Issuer() != currentAuthority {
			return Capability{}, verrs.NewPrincipalAlignmentError(currentAuthority, prf)
		}

		currentAuthority = prf.Audience()
		var err error
		currentCapability, err = currentCapability.Attenuate(prf.Command(), prf.Policy())
		if err != nil {
			return Capability{}, err
		}
	}

	if currentAuthority != inv.Issuer() {
		if len(prfs) == 0 {
			// The spec fixtures call this out as a different error case from a
			// principal alignment error (`InvalidAudience`).
			return Capability{}, verrs.NewInvalidClaimError(fmt.Sprintf("invocation %s is not issued by subject and has no proofs", inv.Link()))
		}
		return Capability{}, verrs.NewPrincipalAlignmentError(currentAuthority, inv)
	}

	return currentCapability, nil
}

// ProofResolverFunc finds a delegation corresponding to an external proof link.
type ProofResolverFunc func(ctx context.Context, link cid.Cid) (ucan.Delegation, error)

// NonStandardSignatureVerifierFunc is used to verify signatures from
// non-standard signature algorithms. It can be passed into a UCAN validator in
// order to support delegations signed with non-standard signature algorithms.
type NonStandardSignatureVerifierFunc func(ctx context.Context, token ucan.Token, meta ucan.Container) error

// ProofUnavailable is a [ProofResolverFunc] that always fails.
func ProofUnavailable(ctx context.Context, p cid.Cid) (ucan.Delegation, error) {
	return nil, verrs.NewUnavailableProofError(p, errors.New("no proof resolver configured"))
}

// FailNonStandardSignatureVerification is a [NonStandardSignatureVerifierFunc]
// that always fails.
func FailNonStandardSignatureVerification(ctx context.Context, token ucan.Token, meta ucan.Container) error {
	return verrs.NewUnverifiableSignatureError(token, errors.New("no non-standard signature verifier configured"))
}

func ProofsFromContainer(c ucan.Container) ProofResolverFunc {
	return func(ctx context.Context, l cid.Cid) (ucan.Delegation, error) {
		prf, ok := c.Delegation(l)
		if !ok {
			return nil, verrs.NewUnavailableProofError(l, errors.New("proof not found in container"))
		}
		return prf, nil
	}
}

func ValidateNotExpired(token ucan.Token, now ucan.UnixTimestamp) error {
	exp := token.Expiration()
	if exp == nil {
		return nil
	}
	if *exp <= now {
		return verrs.NewExpiredError(token)
	}
	return nil
}

func ValidateNotTooEarly(dlg ucan.Delegation, now ucan.UnixTimestamp) error {
	nbf := dlg.NotBefore()
	if nbf == nil {
		return nil
	}
	if *nbf != 0 && now <= *nbf {
		return verrs.NewTooEarlyError(dlg)
	}
	return nil
}
