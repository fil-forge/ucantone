package validator

import "github.com/fil-forge/ucantone/ucan"

type validationConfig struct {
	resolveProof               ProofResolverFunc
	resolveDIDVerifier         DIDVerifierResolverFunc
	validationTime             ucan.UTCUnixTimestamp
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

func WithVerifierResolver(resolveDIDKey DIDVerifierResolverFunc) Option {
	return func(vc *validationConfig) {
		vc.resolveDIDVerifier = resolveDIDKey
	}
}

func WithValidationTime(now ucan.UTCUnixTimestamp) Option {
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
