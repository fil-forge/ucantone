package examples

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fil-forge/ucantone/examples/types"
	"github.com/fil-forge/ucantone/examples/types/fields"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/validator"
)

// TestTypedPolicyEndToEnd walks the full lifecycle of a *typed* delegation
// policy: a service delegates a command to a user under a policy, the user
// invokes the command, and the validator enforces the policy against the
// invocation's arguments.
//
// The policy is authored against generated field descriptors
// (examples/types/fields, produced from types.MessageSendArguments by the
// fieldgen generator). Each builder takes a typed Selector, so:
//
//   - the comparison value is checked against the field's Go type, and
//   - the selector path (".to", ".subject", ...) is derived from a real field.
//
// A wrong-typed value or a mistyped path is therefore a compile error, not a
// policy that silently never matches at runtime. For example, these would not
// compile:
//
//	policy.Eq(fields.MessageSendArguments.Subject, 42)   // .subject is a string field
//	policy.Glob(fields.MessageSendArguments.To, "*")     // .to is a SliceSelector, not Selector[string]
//	policy.Gt(fields.MessageSendArguments.To, nil)       // a list field is not Ordered
//
// The builders return the same policy.StatementBuilderFunc as the legacy
// string-selector builders, so they drop straight into
// delegation.WithPolicyBuilder and reuse the matcher and wire format unchanged.
func TestTypedPolicyEndToEnd(t *testing.T) {
	// mailer owns the /message/send capability; alice is the user it delegates to.
	mailer, err := ed25519.Generate()
	require.NoError(t, err)
	alice, err := ed25519.Generate()
	require.NoError(t, err)

	const messageSend = "/message/send"

	// mailer delegates /message/send to alice, but constrains how she may use
	// it with a typed policy:
	//   - every recipient must be an example.com address,
	//   - the subject must not be empty, and
	//   - the message body must mention "ucantone".
	dlg, err := delegation.Delegate(
		mailer,       // issuer (root authority over the capability)
		alice.DID(),  // audience (who receives the delegation)
		mailer.DID(), // subject (the resource the capability acts on)
		messageSend,  // command
		delegation.WithPolicyBuilder(
			// fields.MessageSendArguments.To is a SliceSelector[Selector[string]];
			// Each hands the closure the element descriptor — here an identity
			// Selector[string] pointing at each address in turn.
			policy.Each(fields.MessageSendArguments.To, func(addr policy.Selector[string]) []policy.StatementBuilderFunc {
				return []policy.StatementBuilderFunc{policy.Glob(addr, "*@example.com")}
			}),
			// .subject is a Selector[string]; Ne pins the value type to string.
			policy.Ne(fields.MessageSendArguments.Subject, ""),
			policy.Glob(fields.MessageSendArguments.Message, "*ucantone*"),
		),
	)
	require.NoError(t, err)

	// invoke builds a /message/send invocation carrying typed arguments and the
	// delegation above as proof of authority.
	invoke := func(args *types.MessageSendArguments) ucan.Invocation {
		inv, err := invocation.Invoke(alice, mailer.DID(), messageSend, args, invocation.WithProofs(dlg.Link()))
		require.NoError(t, err)
		return inv
	}

	// validate runs the full pipeline: signature + time bounds + proof chain +
	// the policy check (cap.Allows -> policy.Match) against the decoded args.
	// The delegation is supplied to the validator via a container so its proof
	// resolver can walk the chain.
	validate := func(inv ucan.Invocation) error {
		return validator.ValidateInvocation(t.Context(), inv,
			validator.WithProofResolver(validator.ProofsFromContainer(
				container.New(container.WithDelegations(dlg)),
			)),
		)
	}

	// 1) A fully conforming invocation passes validation.
	require.NoError(t, validate(invoke(&types.MessageSendArguments{
		To:      []string{"bob@example.com", "carol@example.com"},
		Subject: "Status update",
		Message: "the ucantone migration is done",
	})), "all clauses satisfied")

	// 2) A recipient outside example.com is rejected by the Each/Glob clause.
	require.Error(t, validate(invoke(&types.MessageSendArguments{
		To:      []string{"bob@example.com", "mallory@evil.test"},
		Subject: "Status update",
		Message: "the ucantone migration is done",
	})), "a non-example.com recipient violates the policy")

	// 3) An empty subject is rejected by the Ne clause.
	require.Error(t, validate(invoke(&types.MessageSendArguments{
		To:      []string{"bob@example.com"},
		Subject: "",
		Message: "the ucantone migration is done",
	})), "an empty subject violates the policy")

	// 4) A message that doesn't mention "ucantone" is rejected by the Glob clause.
	require.Error(t, validate(invoke(&types.MessageSendArguments{
		To:      []string{"bob@example.com"},
		Subject: "Status update",
		Message: "unrelated chatter",
	})), "a message missing the keyword violates the policy")
}
