package bindcom

import (
	cbg "github.com/whyrusleeping/cbor-gen"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
)

type Arguments interface {
	cbg.CBORMarshaler
}

// Command that can be used to validate an invocation against proof policies.
type Command[A Arguments] command.Command

// New creates a validated command from the provided list of segment strings.
// An error is returned if an invalid Command would be formed
func New[A Arguments](segments ...string) Command[A] {
	return Command[A](command.New(segments...))
}

// Parse verifies that the provided string contains the required [segment
// structure] and, if valid, returns the resulting Command.
//
// [segment structure]: https://github.com/ucan-wg/spec#segment-structure
func Parse[A Arguments](s string) (Command[A], error) {
	cmd, err := command.Parse(s)
	if err != nil {
		return "", err
	}
	return Command[A](cmd), nil
}

func (c Command[A]) Delegate(issuer ucan.Signer, audience did.DID, subject did.DID, options ...delegation.Option) (*delegation.Delegation, error) {
	return delegation.Delegate(issuer, audience, subject, command.Command(c), options...)
}

func (c Command[A]) Invoke(issuer ucan.Signer, subject did.DID, arguments A, options ...invocation.Option) (*invocation.Invocation, error) {
	return invocation.Invoke(issuer, subject, command.Command(c), arguments, options...)
}
