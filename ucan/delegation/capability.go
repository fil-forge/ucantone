package delegation

import (
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
)

type Capability struct {
	sub did.DID
	cmd ucan.Command
	pol ucan.Policy
}

func NewCapability(subject did.DID, command ucan.Command, policy ucan.Policy) Capability {
	return Capability{subject, command, policy}
}

func (c Capability) Command() ucan.Command {
	return c.cmd
}

func (c Capability) Policy() ucan.Policy {
	return c.pol
}

func (c Capability) Subject() did.DID {
	return c.sub
}

var _ ucan.Capability = (*Capability)(nil)
