package delegation

import (
	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
)

// Option is an option configuring a UCAN invocation.
type Option func(cfg *delegationConfig) error

type delegationConfig struct {
	exp   *ucan.UTCUnixTimestamp
	nbf   *ucan.UTCUnixTimestamp
	noexp bool
	nnc   []byte
	nonnc bool
	meta  ipld.Map
	pol   policy.Policy
}

// WithExpiration configures the expiration time in UTC seconds since Unix
// epoch.
func WithExpiration(exp ucan.UTCUnixTimestamp) Option {
	return func(cfg *delegationConfig) error {
		cfg.exp = &exp
		cfg.noexp = false
		return nil
	}
}

// WithNoExpiration configures the UCAN to never expire.
//
// WARNING: this will cause the delegation to be valid FOREVER, unless revoked.
func WithNoExpiration() Option {
	return func(cfg *delegationConfig) error {
		cfg.exp = nil
		cfg.noexp = true
		return nil
	}
}

// WithNonce configures the nonce value for the UCAN.
func WithNonce(nnc []byte) Option {
	return func(cfg *delegationConfig) error {
		cfg.nnc = nnc
		return nil
	}
}

// WithNoNonce configures an empty nonce value for the UCAN.
func WithNoNonce() Option {
	return func(cfg *delegationConfig) error {
		cfg.nonnc = true
		return nil
	}
}

// WithNotBefore configures the time in UTC seconds since Unix epoch that the
// delegation becomes valid.
func WithNotBefore(nbf ucan.UTCUnixTimestamp) Option {
	return func(cfg *delegationConfig) error {
		cfg.nbf = &nbf
		return nil
	}
}

// WithMetadata configures the arbitrary metadata for the UCAN.
func WithMetadata(meta ipld.Map) Option {
	return func(cfg *delegationConfig) error {
		cfg.meta = meta
		return nil
	}
}

func WithPolicy(pol ucan.Policy) Option {
	return func(cfg *delegationConfig) error {
		pol, err := policy.New(pol.Statements()...)
		if err != nil {
			return err
		}
		cfg.pol = pol
		return nil
	}
}

// WithPolicyBuilder configures the policy for the delegation, by building a
// policy from the passed statement builder functions.
func WithPolicyBuilder(statements ...policy.StatementBuilderFunc) Option {
	return func(cfg *delegationConfig) error {
		pol, err := policy.Build(statements...)
		if err != nil {
			return err
		}
		cfg.pol = pol
		return nil
	}
}
