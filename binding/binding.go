// Package binding provides Binding, a typed UCAN command: a command path paired
// with the Go types of the arguments it accepts (Args) and the result it
// returns (OK). A Binding makes those types the single definition for a
// command, so they are checked consistently everywhere the command is used:
//
//   - Invoke encodes Args into an invocation (on the client).
//   - A handler decodes Args from the invocation and encodes OK into the
//     receipt (on the server), through [Request][Args] and [Response][OK].
//   - Unpack decodes OK out of the receipt (on the client).
//
// These checks happen at compile time. The wire is still validated at run time:
// a peer may send bytes that do not conform to Args or OK, which surfaces as a
// decode error.
//
// Declare each command once with [Bind] and a command from the command package,
// then derive every use from that one value:
//
//	var Info = binding.Bind[*InfoArgs, *InfoOK](command.MustParse("/space/info"))
//
//	inv, err := Info.Invoke(issuer, subject, &InfoArgs{...}) // client
//	out, err := Info.Unpack(receipt)                         // client
//
// On the server, register a handler for the command in one of three ways,
// from most to least typed:
//
//   - server.NewRoute bundles the command and a typed handler into a Route,
//     so they cannot diverge — the usual choice.
//   - [Binding.Handler] (or the free [NewHandler]) adapts a typed handler into
//     the untyped [execution.HandlerFunc] a server registers.
//   - registering a raw [execution.HandlerFunc] against the embedded
//     [command.Command] directly, bypassing Args/OK typing, when a handler
//     needs the lower-level request and response (e.g. custom transport
//     metadata).
//
// See the package example for the full client-and-server round trip.
package binding

import (
	"bytes"
	"fmt"

	cbg "github.com/whyrusleeping/cbor-gen"

	"github.com/fil-forge/ucantone/did"
	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
)

// CBORValue is any value that round-trips through CBOR: marshalled into a UCAN
// (e.g. an invocation's arguments or a receipt's result) and unmarshalled back
// out again. It is the single contract a typed command's argument and result
// types must satisfy.
type CBORValue interface {
	cbg.CBORMarshaler
	cbg.CBORUnmarshaler
}

// Binding ties a command to its typed argument (Args) and result (OK) types.
// Both must round-trip through CBOR ([CBORValue]): Args is encoded by
// Invoke and decoded when the command is handled; OK is encoded by the handler
// and decoded by Unpack.
type Binding[Args, OK CBORValue] struct {
	command.Command
}

// Bind pairs an already-valid command with the Go types of its arguments
// (Args) and result (OK). The command carries its own validity (it cannot be
// constructed except through command.Parse, command.MustParse, or
// command.New), so Bind cannot fail. Construct or parse the command with the
// command package, then attach its types here:
//
//	b := binding.Bind[*Args, *OK](command.MustParse("/space/info"))
func Bind[Args, OK CBORValue](cmd command.Command) Binding[Args, OK] {
	return Binding[Args, OK]{Command: cmd}
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

// Route adapts a typed handler into an [execution.HandlerFunc] and wraps it in
// a [server.Route] along with the command for registration with a server. The
// handler's argument and result types are checked against the command's Args
// and OK at compile time.
func (c Binding[Args, OK]) Route(fn HandlerFunc[Args, OK]) server.Route {
	return NewRoute(c, fn)
}

// Handler adapts a typed handler into an [execution.HandlerFunc] for
// registration on a server. The handler's argument and result types are
// checked against the command's Args and OK at compile time.
func (c Binding[Args, OK]) Handler(fn HandlerFunc[Args, OK]) execution.HandlerFunc {
	return NewHandler(fn)
}

// Unpack the command's typed result (OK) from a receipt. If the receipt
// reports a failure, Unpack decodes the standard error model and returns
// it as an error.
func (c Binding[Args, OK]) Unpack(rcpt ucan.Receipt) (OK, error) {
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
	return decode[OK](ok)
}
