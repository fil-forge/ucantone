package capability

import (
	"errors"
	"fmt"

	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	"github.com/fil-forge/ucantone/ucan/invocation"
	verrs "github.com/fil-forge/ucantone/validator/errors"
	"github.com/ipfs/go-cid"
)

type Match struct {
	Invocation ucan.Invocation
	Task       ucan.Task
	Proofs     map[cid.Cid]ucan.Delegation
}

// Capability that can be used to validate an invocation against proof policies.
type Capability struct {
	cmd ucan.Command
	pol ucan.Policy
}

// New creates a new capability definition that can be used to validate an
// invocation against proof policies.
func New(cmd ucan.Command, options ...Option) (*Capability, error) {
	cfg := capabilityConfig{pol: policy.Policy{}}
	for _, opt := range options {
		err := opt(&cfg)
		if err != nil {
			return nil, err
		}
	}
	cmd, err := command.Parse(string(cmd))
	if err != nil {
		return nil, fmt.Errorf("parsing command: %w", err)
	}
	return &Capability{cmd, cfg.pol}, nil
}

// Match an invocation against the capability, resulting in a match, which is
// the task from the invocation, verified to be matching with delegation
// policies.
func (c *Capability) Match(inv ucan.Invocation, proofs map[cid.Cid]ucan.Delegation) (*Match, error) {
	ok, err := policy.Match(c.pol, inv.Arguments())
	if !ok {
		return nil, err
	}

	usedProofs := make(map[cid.Cid]ucan.Delegation, len(inv.Proofs()))
	for _, p := range inv.Proofs() {
		prf, ok := proofs[p]
		if !ok {
			return nil, verrs.NewUnavailableProofError(p, errors.New("missing from map"))
		}
		ok, err = policy.Match(prf.Policy(), inv.Arguments())
		if !ok {
			return nil, err
		}
		usedProofs[p] = prf
	}

	return &Match{Invocation: inv, Task: inv.Task(), Proofs: usedProofs}, nil
}

func (c *Capability) Command() ucan.Command {
	return c.cmd
}

func (c *Capability) Policy() ucan.Policy {
	return c.pol
}

func (c *Capability) Delegate(issuer ucan.Signer, audience ucan.Principal, subject ucan.Subject, options ...delegation.Option) (*delegation.Delegation, error) {
	return delegation.Delegate(issuer, audience, subject, c.cmd, options...)
}

func (c *Capability) Invoke(issuer ucan.Signer, subject ucan.Subject, arguments ipld.Map, options ...invocation.Option) (*invocation.Invocation, error) {
	return invocation.Invoke(issuer, subject, c.cmd, arguments, options...)
}
