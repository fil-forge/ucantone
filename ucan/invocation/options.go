package invocation

import (
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

// Option is an option configuring a UCAN invocation.
type Option func(cfg *invocationConfig)

type invocationConfig struct {
	aud   *did.DID
	exp   *ucan.UnixTimestamp
	noexp bool
	nnc   []byte
	nonnc bool
	meta  ipld.Map
	prf   []cid.Cid
	iat   *ucan.UnixTimestamp
	cause *cid.Cid
}

// WithAudience configures the DID of the intended Executor if different from
// the Subject.
func WithAudience(aud did.DID) Option {
	return func(cfg *invocationConfig) {
		cfg.aud = &aud
	}
}

// WithExpiration configures the expiration time in  seconds since Unix
// epoch.
func WithExpiration(exp ucan.UnixTimestamp) Option {
	return func(cfg *invocationConfig) {
		cfg.exp = &exp
		cfg.noexp = false
	}
}

// WithNoExpiration configures the UCAN to never expire.
//
// WARNING: this will cause the delegation to be valid FOREVER, unless revoked.
func WithNoExpiration() Option {
	return func(cfg *invocationConfig) {
		cfg.exp = nil
		cfg.noexp = true
	}
}

// WithNonce configures the nonce value for the UCAN.
func WithNonce(nnc []byte) Option {
	return func(cfg *invocationConfig) {
		cfg.nnc = nnc
	}
}

// WithNoNonce configures an empty nonce value for the UCAN.
func WithNoNonce() Option {
	return func(cfg *invocationConfig) {
		cfg.nonnc = true
	}
}

// WithMetadata configures the arbitrary metadata for the UCAN.
func WithMetadata(meta ipld.Map) Option {
	return func(cfg *invocationConfig) {
		cfg.meta = meta
	}
}

// WithProof configures the proof(s) for the UCAN. If the `issuer` of this
// `Invocation` is not the resource owner / service provider, for the delegated
// capabilities, the `proofs` must contain valid `Proof`s containing
// delegations to the `issuer`.
func WithProofs(prf ...cid.Cid) Option {
	return func(cfg *invocationConfig) {
		cfg.prf = prf
	}
}

// WithIssuedAt sets the time at which the invocation was issued at in
// seconds since Unix epoch.
func WithIssuedAt(iat ucan.UnixTimestamp) Option {
	return func(cfg *invocationConfig) {
		cfg.iat = &iat
	}
}

// WithCause configures the CID of the receipt that enqueued the task.
func WithCause(cause cid.Cid) Option {
	return func(cfg *invocationConfig) {
		cfg.cause = &cause
	}
}
