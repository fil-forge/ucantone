package validator

import "github.com/fil-forge/ucantone/ucan"

type validationConfig struct {
	resolveProof               ProofResolverFunc
	resolveDIDVerifier         DIDVerifierResolverFunc
	validationTime             ucan.UnixTimestamp
	verifyNonStandardSignature NonStandardSignatureVerifierFunc
	metadata                   ucan.Container
}

// Option is an option configuring the validator.
type Option func(*validationConfig)

func WithProofResolver(resolveProof ProofResolverFunc) Option {
	return func(vc *validationConfig) {
		vc.resolveProof = resolveProof
	}
}

// WithVerifierResolver sets the function to be used for resolving a DID to a
// verifier.
func WithVerifierResolver(resolveDIDKey DIDVerifierResolverFunc) Option {
	return func(vc *validationConfig) {
		vc.resolveDIDVerifier = resolveDIDKey
	}
}

// WithVerifierResolvers is a convenience option for composing a verifier
// resolver from multiple DID method-specific resolvers using
// [NewDIDVerifierResolverByMethod].
func WithVerifierResolvers(resolvers VerifierResolverMap) Option {
	return func(vc *validationConfig) {
		vc.resolveDIDVerifier = NewDIDVerifierResolverByMethod(resolvers)
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
