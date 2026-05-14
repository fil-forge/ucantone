package validator

import "github.com/fil-forge/ucantone/ucan"

type validationConfig struct {
	canIssue                   CanIssueFunc
	metadata                   ucan.Container
	parsePrincipal             PrincipalParserFunc
	proofs                     []ucan.Delegation
	resolveProof               ProofResolverFunc
	resolveDIDKey              DIDResolverFunc
	validateAuthorization      ValidateAuthorizationFunc
	validationTime             ucan.UnixTimestamp
	verifyNonStandardSignature NonStandardSignatureVerifierFunc
}

// Option is an option configuring the validator.
type Option func(*validationConfig)

// WithCanIssue informs validator whether given capability can be issued by a
// given principal or whether it needs to be delegated to the issuer.
func WithCanIssue(canIssue CanIssueFunc) Option {
	return func(vc *validationConfig) {
		vc.canIssue = canIssue
	}
}

func WithPrincipalParser(parsePrincipal PrincipalParserFunc) Option {
	return func(vc *validationConfig) {
		vc.parsePrincipal = parsePrincipal
	}
}

func WithProofs(proofs ...ucan.Delegation) Option {
	return func(vc *validationConfig) {
		vc.proofs = append(vc.proofs, proofs...)
	}
}

func WithProofResolver(resolveProof ProofResolverFunc) Option {
	return func(vc *validationConfig) {
		vc.resolveProof = resolveProof
	}
}

func WithDIDResolver(resolveDIDKey DIDResolverFunc) Option {
	return func(vc *validationConfig) {
		vc.resolveDIDKey = resolveDIDKey
	}
}

func WithAuthorizationValidator(validateAuthorization ValidateAuthorizationFunc) Option {
	return func(vc *validationConfig) {
		vc.validateAuthorization = validateAuthorization
	}
}

// WithValidationTime sets the time to be used as "now" when validation is
// performed.
func WithValidationTime(now ucan.UnixTimestamp) Option {
	return func(vc *validationConfig) {
		vc.validationTime = now
	}
}

// WithNonStandardSignatureVerifier sets the function to be used for verifying
// non-standard signature algorithms.
func WithNonStandardSignatureVerifier(verifyNonStandardSignature NonStandardSignatureVerifierFunc) Option {
	return func(vc *validationConfig) {
		vc.verifyNonStandardSignature = verifyNonStandardSignature
	}
}

// WithMetadata sets additional metadata that may be used during validation.
func WithMetadata(meta ucan.Container) Option {
	return func(vc *validationConfig) {
		vc.metadata = meta
	}
}
