package validator

import (
	"errors"
	"fmt"

	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
)

// https://github.com/ucan-wg/spec#capability
type Capability struct {
	sub ucan.Subject
	cmd ucan.Command
	pol ucan.Policy
}

func NewCapability(sub ucan.Subject) Capability {
	return Capability{
		sub: sub,
		cmd: command.Top(),
		pol: policy.Policy{},
	}
}

func (c Capability) Subject() ucan.Subject {
	return c.sub
}

func (c Capability) Command() ucan.Command {
	return c.cmd
}

func (c Capability) Policy() ucan.Policy {
	return c.pol
}

func (c Capability) Constrain(cmd ucan.Command, pol ucan.Policy) (Capability, error) {
	if c.cmd.Proves(cmd) {
		// If the current command proves the new command, then we can constrain to
		// the new command.
		c.cmd = cmd
	} else if cmd.Proves(c.cmd) {
		// If the new command proves the current command, then no change is needed;
		// we already have the more constrained command.
	} else {
		// If neither command proves the other, then we have a conflict and cannot
		// constrain.
		// TK: Needs better error
		return c, errors.New("cannot constrain to an unrelated command")
	}
	var err error
	c.pol, err = policy.New(append(c.pol.Statements(), pol.Statements()...)...)
	if err != nil {
		return c, err
	}
	return c, nil
}

func (c Capability) Allows(sub ucan.Subject, cmd ucan.Command, args ipld.Map) (bool, error) {
	if c.sub.DID() != sub.DID() {
		return false, fmt.Errorf("capability subject %s does not match given subject %s", c.sub.DID(), sub.DID())
	}
	if !c.cmd.Proves(cmd) {
		return false, fmt.Errorf("capability command %s does not prove given command %s", c.cmd, cmd)
	}

	ok, err := policy.Match(c.pol, args)
	if err != nil {
		return false, fmt.Errorf("invocation arguments do not satisfy capability policy: %w", err)
	}
	return ok, nil
}
