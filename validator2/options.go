package validator2

import "github.com/fil-forge/ucantone/ucan"

type validationConfig struct {
	resolveProof       ProofResolverFunc
	resolveDIDVerifier DIDVerifierResolverFunc
	validationTime     ucan.UTCUnixTimestamp
}

// Option is an option configuring the validator.
type Option func(*validationConfig)

func WithProofResolver(resolveProof ProofResolverFunc) Option {
	return func(vc *validationConfig) {
		vc.resolveProof = resolveProof
	}
}

func WithDIDResolver(resolveDIDKey DIDVerifierResolverFunc) Option {
	return func(vc *validationConfig) {
		vc.resolveDIDVerifier = resolveDIDKey
	}
}

func WithValidationTime(now ucan.UTCUnixTimestamp) Option {
	return func(vc *validationConfig) {
		vc.validationTime = now
	}
}
