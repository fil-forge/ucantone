package validator

import (
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/ucan"
)

type validationConfig struct {
	resolveProof               ProofResolverFunc
	didResolver                did.Resolver
	deriveVerifier             VerifierFactoryFunc
	validationTime             ucan.UnixTimestamp
	verifyNonStandardSignature NonStandardSignatureVerifierFunc
	metadata                   ucan.Container
}

func makeCfg(options ...Option) validationConfig {
	cfg := validationConfig{
		resolveProof:               ProofUnavailable,
		didResolver:                key.Resolve,
		deriveVerifier:             DeriveMultikeyVerifier,
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

func WithDIDResolver(resolveDID did.Resolver) Option {
	return func(vc *validationConfig) {
		vc.didResolver = resolveDID
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
