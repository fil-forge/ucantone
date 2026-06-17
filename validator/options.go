package validator

import (
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/ucan"
)

type validationConfig struct {
	resolveProof               ProofResolverFunc
	didResolver                did.Resolver
	verifierFactories          map[string]VerifierFactory
	validationTime             ucan.UnixTimestamp
	verifyNonStandardSignature NonStandardSignatureVerifierFunc
	metadata                   ucan.Container
}

// DefaultFactories returns a map pre-populated with factories for the standard
// verification method types (currently Multikey). It is used by the validator
// when no custom registry is supplied via [WithVerifierRegistry].
func DefaultFactories() map[string]VerifierFactory {
	return map[string]VerifierFactory{
		did.MultikeyVerificationMethodType: multikey.DeriveVerifier,
	}
}

func makeCfg(options ...Option) validationConfig {
	cfg := validationConfig{
		resolveProof:               ProofUnavailable,
		didResolver:                key.Resolver,
		verifierFactories:          DefaultFactories(),
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

// WithVerifierFactories adds factories for deriving verifiers for a specific
// verification method type.
func WithVerifierFactories(factories map[string]VerifierFactory) Option {
	return func(vc *validationConfig) {
		vc.verifierFactories = factories
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
