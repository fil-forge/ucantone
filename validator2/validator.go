// Package validator2 provides [validator2.Validator], which can validate a
// [ucan.Invocation].
package validator2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal/verifier"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/token"
	"github.com/fil-forge/ucantone/validator"
	verrs "github.com/fil-forge/ucantone/validator/errors"
)

// TK: Should Validate return something?

// ValidateInvocation determines whether an [ucan.Invocation] is a valid request
// to execute a task. If an invocation is valid, its audience is expected to
// execute its task. If an invocation is invalid, its audience is expected to
// reject the request.
func ValidateInvocation(
	ctx context.Context,
	invocation ucan.Invocation,
	// authority ucan.Verifier,
	options ...Option,
) error {
	cfg := validationConfig{
		resolveProof:       ProofUnavailable,
		resolveDIDVerifier: ResolveDIDKeyVerifier,
		validationTime:     ucan.UTCUnixTimestamp(time.Now().Unix()),
		// verifyNonStandardSignature: FailNonStandardSignatureVerification,
	}
	for _, opt := range options {
		opt(&cfg)
	}

	// To be valid, an invocation must be a valid token...
	err := ValidateToken(ctx, invocation, cfg)
	if err != nil {
		return err
	}

	// ...and have a valid proof chain...
	cap, err := capabilityFromProofChain(ctx, invocation, cfg)
	if err != nil {
		return err
	}

	// ...and have the capability to perform its task under the proof chain.
	ok, err := cap.Allows(
		invocation.Subject(),
		invocation.Command(),
		invocation.Arguments(),
	)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("invocation is not authorized under the proof chain")
	}

	return nil
}

// ValidateToken determines whether a [ucan.Token] is a valid UCAN token. To be
// valid, a token must have a valid signature from its issuer and be within its
// time bounds. An [ucan.Invocation] is a token, but has additional
// requirements. An invocation may be a valid token but still an invalid
// invocation, if its proof chain is insufficient.
func ValidateToken(ctx context.Context, tok ucan.Token, cfg validationConfig) error {
	// To be valid, a token must have a valid signature from its issuer...
	err := verifyTokenSignature(ctx, tok, cfg.resolveDIDVerifier)
	if err != nil {
		return err
	}

	// ...and not be expired...
	err = validator.ValidateNotExpired(tok, cfg.validationTime)
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
		err = validator.ValidateNotTooEarly(dlg, cfg.validationTime)
		if err != nil {
			return err
		}
	}

	return nil
}

// verifyTokenSignature verifies the token was signed by the passed verifier.
func verifyTokenSignature(ctx context.Context, tok ucan.Token, resolveDIDVerifier DIDVerifierResolverFunc) error {
	verifier, err := resolveDIDVerifier(ctx, tok.Issuer().DID())
	if err != nil {
		return err
	}

	ok, err := token.VerifySignature(tok, verifier)
	if err != nil {
		return err
	}
	if !ok {
		return verrs.NewInvalidSignatureError(tok, verifier)
	}
	return nil
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
		if err := ValidateToken(ctx, prf, cfg); err != nil {
			return Capability{}, err
		}

		if prf.Issuer().DID() != currentAuthority.DID() {
			return Capability{}, NewProofChainError(inv.Subject(), prfs[:i], prf)
		}

		// Subjects must match, or subject must be nil (powerline delegation).
		if prf.Subject() != nil && prf.Subject().DID() != inv.Subject().DID() {
			return Capability{}, NewProofChainError(inv.Subject(), prfs[:i], prf)
		}

		currentAuthority = prf.Audience()
		var err error
		currentCapability, err = currentCapability.Constrain(prf.Command(), prf.Policy())
		if err != nil {
			return Capability{}, fmt.Errorf("proof chain is broken at proof %d: %w", i, err)
		}
	}

	if currentAuthority.DID() != inv.Issuer().DID() {
		return Capability{}, errors.New("ERROR TK: invocation issuer does not match final authority in proof chain")
	}

	return currentCapability, nil
}

func NewProofChainError(sub ucan.Principal, priorPrfs []ucan.Delegation, badPrf ucan.Delegation) error {
	prs := []string{sub.DID().String()}
	for _, pf := range priorPrfs {
		prs = append(prs, pf.Audience().DID().String())
	}
	// "Error: Proof chain is broken (did:example:alice → did:example:bob, but
	// next proof is did:example:eve → did:example:mallory)"
	return fmt.Errorf("Proof chain is broken (%v, next proof is %v → %v)", strings.Join(prs, " → "), badPrf.Issuer().DID(), badPrf.Audience().DID())
}

// ProofResolverFunc finds a delegation corresponding to an external proof link.
type ProofResolverFunc func(ctx context.Context, link ucan.Link) (ucan.Delegation, error)

// DIDVerifierResolverFunc is used to resolve the verification methods of a
// DID. It returns a [ucan.Verifier] that can verify signatures from the given
// DID.
type DIDVerifierResolverFunc func(ctx context.Context, nonDIDKey did.DID) (ucan.Verifier, error)

// ProofUnavailable is a [ProofResolverFunc] that always fails.
func ProofUnavailable(ctx context.Context, p ucan.Link) (ucan.Delegation, error) {
	return nil, verrs.NewUnavailableProofError(p, errors.New("no proof resolver configured"))
}

func ProofsFromContainer(c *container.Container) ProofResolverFunc {
	return func(ctx context.Context, l ucan.Link) (ucan.Delegation, error) {
		prf, ok := c.Delegation(l)
		if !ok {
			return nil, verrs.NewUnavailableProofError(l, errors.New("proof not found in container"))
		}
		return prf, nil
	}
}

// ResolveDIDKeyVerifier is a [DIDVerifierResolverFunc] that only supports `did:key`
// DIDs and returns an error for any other DID method.
func ResolveDIDKeyVerifier(ctx context.Context, d did.DID) (ucan.Verifier, error) {
	return verifier.Parse(d.String())
}
