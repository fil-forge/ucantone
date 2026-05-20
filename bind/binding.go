// Package bind provides Binding, a typed UCAN command: a command path paired
// with the Go types of the arguments it accepts (Args) and the result it
// returns (OK). A Binding makes those types the single definition for a
// command, so they are checked consistently everywhere the command is used:
//
//   - Invoke encodes Args into an invocation (on the client).
//   - A handler decodes Args from the invocation and encodes OK into the
//     receipt (on the server), through Request[Args] and Response[OK].
//   - ReadResult decodes OK out of the receipt (on the client).
//
// These checks happen at compile time. The wire is still validated at run time:
// a peer may send bytes that do not conform to Args or OK, which surfaces as a
// decode error.
package bind

import (
	"bytes"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/internal/cbordec"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
)

// Binding ties a command to its typed argument (Args) and result (OK) types.
// Both must round-trip through CBOR ([ucan.CBORValue]): Args is encoded by
// Invoke and decoded when the command is handled; OK is encoded by the handler
// and decoded by ReadResult.
type Binding[Args, OK ucan.CBORValue] struct {
	command.Command
}

// New creates a binding from the provided command segments.
func New[Args, OK ucan.CBORValue](segments ...string) Binding[Args, OK] {
	return Binding[Args, OK]{Command: command.New(segments...)}
}

// Parse verifies that s is a well-formed command and returns its binding.
func Parse[Args, OK ucan.CBORValue](s string) (Binding[Args, OK], error) {
	cmd, err := command.Parse(s)
	if err != nil {
		return Binding[Args, OK]{}, err
	}
	return Binding[Args, OK]{Command: cmd}, nil
}

// Invoke constructs a signed invocation of the command carrying the given
// typed arguments.
func (c Binding[Args, OK]) Invoke(issuer ucan.Signer, subject did.DID, arguments Args, options ...invocation.Option) (ucan.Invocation, error) {
	return invocation.Invoke(issuer, subject, c.Command, arguments, options...)
}

// Delegate issues a delegation granting authority over this command. It does
// not involve the argument or result types.
func (c Binding[Args, OK]) Delegate(issuer ucan.Signer, audience did.DID, subject did.DID, options ...delegation.Option) (ucan.Delegation, error) {
	return delegation.Delegate(issuer, audience, subject, c.Command, options...)
}

// Handler adapts a typed handler into an [execution.HandlerFunc] for
// registration on a server. The handler's argument and result types are
// checked against the command's Args and OK at compile time.
func (c Binding[Args, OK]) Handler(fn HandlerFunc[Args, OK]) execution.HandlerFunc {
	return NewHandler(fn)
}

// ReadResult decodes the command's typed result (OK) from a receipt. If the
// receipt reports a failure, ReadResult decodes the standard error model and
// returns it as an error.
func (c Binding[Args, OK]) ReadResult(rcpt ucan.Receipt) (OK, error) {
	var zero OK
	out := rcpt.Out()
	ok, errBytes := out.Unpack()
	if out.IsErr() {
		var model edm.ErrorModel
		if err := model.UnmarshalCBOR(bytes.NewReader(errBytes)); err != nil {
			return zero, fmt.Errorf("decoding execution failure: %w", err)
		}
		return zero, fmt.Errorf("executing %s: %w", c.Command, model)
	}
	return cbordec.Decode[OK](ok)
}
