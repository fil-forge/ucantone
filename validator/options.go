package validator

import (
	"time"

	"github.com/fil-forge/ucantone/ucan"
)

type validationConfig struct {
	resolveProof               ProofResolverFunc
	resolveDIDVerifier         DIDVerifierResolverFunc
	validationTime             ucan.UnixTimestamp
	verifyNonStandardSignature NonStandardSignatureVerifierFunc
	metadata                   ucan.Container
}

func makeCfg(options ...Option) validationConfig {
	cfg := validationConfig{
		resolveProof:               ProofUnavailable,
		resolveDIDVerifier:         ResolveDIDKeyVerifier,
		validationTime:             ucan.UnixTimestamp(time.Now().Unix()),
		verifyNonStandardSignature: FailNonStandardSignatureVerification,
	}
	for _, opt := range options {
		opt(&cfg)
	}
	return cfg
}

// Option is an option configuring the validator.
type Option func(*validationConfig)

func WithProofResolver(resolveProof ProofResolverFunc) Option {
	return func(vc *validationConfig) {
		vc.resolveProof = resolveProof
	}
}

// WithDIDVerifierResolver sets the function to be used for resolving a DID to a
// verifier.
func WithDIDVerifierResolver(resolveDIDVerifier DIDVerifierResolverFunc) Option {
	return func(vc *validationConfig) {
		vc.resolveDIDVerifier = resolveDIDVerifier
	}
}

// WithDIDVerifierResolvers is a convenience option for composing a verifier
// resolver from multiple DID method-specific resolvers using
// [NewDIDVerifierResolverByMethod].
func WithDIDVerifierResolvers(resolvers VerifierResolverMap) Option {
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

// withConfig reuses an entire built [validationConfig].
func withConfig(cfg validationConfig) Option {
	return func(vc *validationConfig) {
		*vc = cfg
	}
}
