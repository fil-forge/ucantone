package validator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal"
	edverifier "github.com/fil-forge/ucantone/principal/ed25519/verifier"
	"github.com/fil-forge/ucantone/principal/verifier"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	"github.com/fil-forge/ucantone/ucan/token"
	"github.com/fil-forge/ucantone/validator/capability"
	verrs "github.com/fil-forge/ucantone/validator/errors"
	"github.com/fil-forge/ucantone/varsig/algorithm/nonstandard"
	"github.com/ipfs/go-cid"
)

// Capability is a capability definition that can be used to validate an
// invocation and against it's proof policies.
type Capability interface {
	// Command is the command the capability matches against.
	Command() ucan.Command
	// Match an invocation against the capability, resulting in a match, which is
	// the task from the invocation, verified to be matching with delegation
	// policies.
	Match(invocation ucan.Invocation, proofs map[cid.Cid]ucan.Delegation) (*capability.Match, error)
}

// Authorization is the details of an invocation that has been validated by the
// validator.
type Authorization struct {
	// Invocation is the invocation that was validated by the validator.
	Invocation ucan.Invocation
	// Proofs are the path of authority from the subject to the invoker. They are
	// delegations starting from the root Delegation (issued by the subject), in
	// strict sequence where the audience of the previous delegation matches the
	// issuer of the next Delegation.
	Proofs map[cid.Cid]ucan.Delegation
	Task   ucan.Task
}

// ProofResolverFunc finds a delegation corresponding to an external proof link.
type ProofResolverFunc func(ctx context.Context, link ucan.Link) (ucan.Delegation, error)

// CanIssueFunc determines whether given capability can be issued by a given
// principal or whether it needs to be delegated to the issuer.
type CanIssueFunc func(capability ucan.Capability, issuer ucan.Principal) bool

// ValidateAuthorizationFunc allows an authorization to be validated further. It
// is typically used to check that the delegations from the authorization have
// not been revoked. It returns `nil` on success.
type ValidateAuthorizationFunc func(ctx context.Context, auth Authorization) error

// DIDResolverFunc is used to resolve a key of the principal that is
// identified by DID different from did:key method. It can be passed into a
// UCAN validator in order to augment it with additional DID methods support.
type DIDResolverFunc func(ctx context.Context, nonDIDKey did.DID) ([]did.DID, error)

// PrincipalParserFunc provides verifier instances that can validate UCANs
// issued by a given principal.
type PrincipalParserFunc func(str string) (principal.Verifier, error)

// NonStandardSignatureVerifierFunc is used to verify signatures from
// non-standard signature algorithms. It can be passed into a UCAN validator in
// order to support delegations signed with non-standard signature algorithms.
type NonStandardSignatureVerifierFunc func(ctx context.Context, token ucan.Token, meta ucan.Container) error

// ValidationContext is the contextual information required by the validator in
// order to validate the delegation chain of an invocation.
type ValidationContext struct {
	// Authority is the identity of the local authority, used to verify signatures
	// of delegations signed by it.
	//
	// A capability provider service will use one corresponding to own DID or it's
	// supervisor's DID if it acts under it's authority.
	//
	// It also allows a service identified by non did:key e.g. did:web or did:dns
	// to pass a resolved key so it does not need to be resolved at runtime.
	Authority ucan.Verifier
	// CanIssue informs validator whether given capability can be issued by a
	// given principal or whether it needs to be delegated to the issuer. By
	// default, the validator will permit self signed invocations/delegations.
	CanIssue CanIssueFunc
	// ParsePrincipal provides verifier instances that can validate UCANs issued
	// by a given principal.
	ParsePrincipal PrincipalParserFunc
	// ResolveProof finds a delegation corresponding to a proof link.
	ResolveProof ProofResolverFunc
	// ResolveDIDKey is a function that resolves the key of a principal that is
	// identified by a DID method different from did:key.
	ResolveDIDKey DIDResolverFunc
	// ValidateAuthorization is called after an invocation has been validated to
	// allow an authorization to be validated further. It is typically used to
	// check that the delegations from the authorization have
	// not been revoked. It returns `nil` on success.
	ValidateAuthorization ValidateAuthorizationFunc
}

// Access validates the invocation issuer is authorized to invoke the delegated
// capability.
//
// The authority is the identity of the local authority, used to verify
// signatures of delegations signed by it.
//
// A capability provider service will use one corresponding to own DID or it's
// supervisor's DID if it acts under it's authority.
//
// It also allows a service identified by non did:key e.g. did:web or did:dns
// to pass a resolved key so it does not need to be resolved at runtime.
func Access(
	ctx context.Context,
	authority ucan.Verifier,
	capability Capability,
	invocation ucan.Invocation,
	options ...Option,
) (Authorization, error) {
	cfg := validationConfig{
		canIssue:                   IsSelfIssued,
		parsePrincipal:             ParsePrincipal,
		resolveProof:               ProofUnavailable,
		resolveDIDKey:              FailDIDKeyResolution,
		validateAuthorization:      NopValidateAuthorization,
		validationTime:             ucan.UTCUnixTimestamp(time.Now().Unix()),
		verifyNonStandardSignature: FailNonStandardSignatureVerification,
	}
	for _, opt := range options {
		opt(&cfg)
	}

	proofs := map[cid.Cid]ucan.Delegation{}
	for _, p := range cfg.proofs {
		proofs[p.Link()] = p
	}

	proofs, err := ResolveProofs(ctx, proofs, cfg.resolveProof, invocation.Proofs())
	if err != nil {
		return Authorization{}, err
	}

	err = Validate(ctx, authority, cfg.canIssue, cfg.parsePrincipal, cfg.resolveDIDKey, cfg.verifyNonStandardSignature, cfg.validationTime, invocation, proofs, cfg.metadata)
	if err != nil {
		return Authorization{}, err
	}

	match, err := capability.Match(invocation, proofs)
	if err != nil {
		return Authorization{}, err
	}

	return Authorization{
		Invocation: invocation,
		Task:       match.Task,
		Proofs:     match.Proofs,
	}, nil
}

func ResolveProofs(ctx context.Context, providedProofs map[cid.Cid]ucan.Delegation, resolve ProofResolverFunc, links []ucan.Link) (map[cid.Cid]ucan.Delegation, error) {
	proofs := map[cid.Cid]ucan.Delegation{}
	for _, link := range links {
		prf, ok := providedProofs[link]
		if !ok {
			var err error
			prf, err = resolve(ctx, link)
			if err != nil {
				return nil, verrs.NewUnavailableProofError(link, err)
			}
		}
		proofs[link] = prf
	}
	return proofs, nil
}

// Validate an invocation to check it is within the time bounds and that it is
// authorized by the issuer.
func Validate(
	ctx context.Context,
	authority ucan.Verifier,
	canIssue CanIssueFunc,
	parsePrincipal PrincipalParserFunc,
	resolveDIDKey DIDResolverFunc,
	verifyNonStandardSignature NonStandardSignatureVerifierFunc,
	now ucan.UTCUnixTimestamp,
	inv ucan.Invocation,
	prfs map[cid.Cid]ucan.Delegation,
	meta ucan.Container,
) error {
	err := ValidateNotExpired(inv, now)
	if err != nil {
		return err
	}

	for _, p := range prfs {
		err := ValidateNotExpired(p, now)
		if err != nil {
			return err
		}
		err = ValidateNotTooEarly(p, now)
		if err != nil {
			return err
		}
	}

	return VerifyAuthorization(ctx, authority, canIssue, parsePrincipal, resolveDIDKey, verifyNonStandardSignature, inv, prfs, meta)
}

func ValidateNotExpired(token ucan.Token, now ucan.UTCUnixTimestamp) error {
	exp := token.Expiration()
	if exp == nil {
		return nil
	}
	if *exp <= now {
		return verrs.NewExpiredError(token)
	}
	return nil
}

func ValidateNotTooEarly(dlg ucan.Delegation, now ucan.UTCUnixTimestamp) error {
	nbf := dlg.NotBefore()
	if nbf == nil {
		return nil
	}
	if *nbf != 0 && now <= *nbf {
		return verrs.NewTooEarlyError(dlg)
	}
	return nil
}

// VerifyAuthorization verifies that the invocation has been authorized by the
// issuer. If issued by the did:key principal it checks that the signature is
// valid. If issued by the root authority it checks that the signature is valid.
// If issued by the principal identified by other DID method attempts to resolve
// a valid `ucan/attest` attestation from the authority, if attestation is not
// found falls back to resolving did:key for the issuer and verifying its
// signature.
func VerifyAuthorization(
	ctx context.Context,
	authority ucan.Verifier,
	canIssue CanIssueFunc,
	parsePrincipal PrincipalParserFunc,
	resolveDIDKey DIDResolverFunc,
	verifyNonStandardSignature NonStandardSignatureVerifierFunc,
	inv ucan.Invocation,
	prfs map[cid.Cid]ucan.Delegation,
	meta ucan.Container,
) error {
	issuer := inv.Issuer().DID()
	// If the issuer is a did:key we just verify a signature
	if strings.HasPrefix(issuer.String(), "did:key:") {
		verifier, err := parsePrincipal(issuer.String())
		if err != nil {
			return verrs.NewUnverifiableSignatureError(inv, err)
		}
		if err := VerifyTokenSignature(inv, verifier); err != nil {
			return err
		}
	} else if inv.Issuer().DID() == authority.DID() {
		if err := VerifyTokenSignature(inv, authority); err != nil {
			return err
		}
	} else if inv.Signature().Header().SignatureAlgorithm().Code() == nonstandard.Code {
		if err := verifyNonStandardSignature(ctx, inv, meta); err != nil {
			return err
		}
	} else {
		// Otherwise we try to resolve did:key from the DID instead
		// and use that to verify the signature
		ids, err := resolveDIDKey(ctx, issuer)
		if err != nil {
			return err
		}

		var verifyErr error
		for _, id := range ids {
			vfr, err := parsePrincipal(id.String())
			if err != nil {
				verifyErr = err
				continue
			}
			wvfr, err := verifier.Wrap(vfr, issuer)
			if err != nil {
				verifyErr = err
				continue
			}
			err = VerifyTokenSignature(inv, wvfr)
			if err != nil {
				verifyErr = err
				continue
			}
			break
		}
		if verifyErr != nil {
			return verrs.NewUnverifiableSignatureError(inv, verifyErr)
		}
	}

	prfChain := inv.Proofs()
	if len(prfChain) > 0 {
		prf, ok := prfs[prfChain[len(prfChain)-1]]
		if !ok {
			return verrs.NewUnavailableProofError(prfChain[len(prfChain)-1], errors.New("missing from map"))
		}

		// check principal alignment
		if inv.Issuer().DID() != prf.Audience().DID() {
			return verrs.NewPrincipalAlignmentError(inv.Issuer(), prf)
		}

		for i, p := range prfChain {
			prf, ok := prfs[p]
			if !ok {
				return verrs.NewUnavailableProofError(p, errors.New("missing from map"))
			}
			issuer := prf.Issuer().DID()

			// this is the root delegation
			if i == 0 {
				// powerline is not allowed as root delegation.
				// a priori there is no such thing as a null subject.
				if prf.Subject() == nil {
					return verrs.NewInvalidClaimError("root delegation subject is null")
				}
				if prf.Subject().DID() != inv.Subject().DID() {
					return verrs.NewSubjectAlignmentError(inv.Subject(), prf)
				}
				// check root issuer/subject alignment
				if !canIssue(ucan.Capability(prf), prf.Issuer()) {
					return verrs.NewInvalidClaimError(fmt.Sprintf("%q cannot issue delegations for %q", issuer, prf.Subject().DID()))
				}
			} else {
				// otherwise check subject and principal alignment
				if prf.Subject() != nil && prf.Subject().DID() != inv.Subject().DID() {
					return verrs.NewSubjectAlignmentError(inv.Subject(), prf)
				}
				prev := prfs[inv.Proofs()[i-1]]
				if issuer != prev.Audience().DID() {
					return verrs.NewPrincipalAlignmentError(prf.Issuer(), prev)
				}
			}

			// If the issuer is a did:key we just verify a signature
			if strings.HasPrefix(issuer.String(), "did:key:") {
				verifier, err := parsePrincipal(issuer.String())
				if err != nil {
					return verrs.NewUnverifiableSignatureError(prf, err)
				}
				if err := VerifyTokenSignature(prf, verifier); err != nil {
					return err
				}
			} else if issuer == authority.DID() {
				if err := VerifyTokenSignature(prf, authority); err != nil {
					return err
				}
			} else if prf.Signature().Header().SignatureAlgorithm().Code() == nonstandard.Code {
				if err := verifyNonStandardSignature(ctx, prf, meta); err != nil {
					return err
				}
			} else {
				// Otherwise we try to resolve did:key from the DID instead
				// and use that to verify the signature
				ids, err := resolveDIDKey(ctx, issuer)
				if err != nil {
					return err
				}

				var verifyErr error
				for _, id := range ids {
					vfr, err := parsePrincipal(id.String())
					if err != nil {
						verifyErr = err
						continue
					}
					wvfr, err := verifier.Wrap(vfr, issuer)
					if err != nil {
						verifyErr = err
						continue
					}
					err = VerifyTokenSignature(prf, wvfr)
					if err != nil {
						verifyErr = err
						continue
					}
					break
				}
				if verifyErr != nil {
					return verrs.NewUnverifiableSignatureError(prf, verifyErr)
				}
			}
		}
	} else {
		// check invocation issuer/subject alignment
		cap := delegation.NewCapability(inv.Subject(), inv.Command(), policy.Policy{})
		if !canIssue(cap, inv.Issuer()) {
			return verrs.NewInvalidClaimError(fmt.Sprintf("%q cannot issue invocations for %q", inv.Issuer().DID(), inv.Subject().DID()))
		}
	}

	return nil
}

// VerifyTokenSignature verifies the token was signed by the passed verifier.
func VerifyTokenSignature(tok ucan.Token, verifier ucan.Verifier) error {
	ok, err := token.VerifySignature(tok, verifier)
	if err != nil {
		return err
	}
	if !ok {
		return verrs.NewInvalidSignatureError(tok, verifier)
	}
	return nil
}

// IsSelfIssued is a [CanIssueFunc] that allows delegations to be self signed.
func IsSelfIssued(capability ucan.Capability, issuer ucan.Principal) bool {
	return capability.Subject().DID() == issuer.DID()
}

// ParsePrincipal is a [PrincipalParser] that supports parsing ed25519 DIDs.
func ParsePrincipal(str string) (principal.Verifier, error) {
	return edverifier.Parse(str)
}

// ProofUnavailable is a [ProofResolverFunc] that always fails.
func ProofUnavailable(ctx context.Context, p ucan.Link) (ucan.Delegation, error) {
	return nil, verrs.NewUnavailableProofError(p, errors.New("no proof resolver configured"))
}

// FailDIDKeyResolution is a [DIDResolverFunc] that always fails.
func FailDIDKeyResolution(ctx context.Context, d did.DID) ([]did.DID, error) {
	return []did.DID{}, verrs.NewDIDKeyResolutionError(d, errors.New("no DID resolver configured"))
}

// FailNonStandardSignatureVerification is a [NonStandardSignatureVerifierFunc]
// that always fails.
func FailNonStandardSignatureVerification(ctx context.Context, token ucan.Token, meta ucan.Container) error {
	return verrs.NewUnverifiableSignatureError(token, errors.New("no non-standard signature verifier configured"))
}

// NopValidateAuthorization is a [ValidateAuthorizationFunc] that does no
// validation and returns nil.
func NopValidateAuthorization(ctx context.Context, auth Authorization) error {
	return nil
}
