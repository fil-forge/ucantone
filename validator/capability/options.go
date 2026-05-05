package capability

import (
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
)

type capabilityConfig struct {
	pol policy.Policy
}

// Option is an option configuring a capability definition.
type Option func(cfg *capabilityConfig) error

// WithPolicy configures the base policy for the capability.
func WithPolicy(pol ucan.Policy) Option {
	return func(cfg *capabilityConfig) error {
		pol, err := policy.New(pol.Statements()...)
		if err != nil {
			return err
		}
		cfg.pol = pol
		return nil
	}
}

// WithPolicyBuilder configures the base policy for the capability, by building
// a policy from the passed statement builder functions.
func WithPolicyBuilder(statements ...policy.StatementBuilderFunc) Option {
	return func(cfg *capabilityConfig) error {
		pol, err := policy.Build(statements...)
		if err != nil {
			return err
		}
		cfg.pol = pol
		return nil
	}
}
