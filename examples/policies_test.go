package examples

import (
	"testing"

	"github.com/fil-forge/ucantone/examples/types/fields"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
)

func TestParsePolicy(t *testing.T) {
	// Create some data to match against the policy:
	msg := ipld.Map{
		"to":      []string{"bob@example.com"},
		"from":    "alice@example.com",
		"message": "Hello bob!",
	}

	// A policy is a list of statements.
	// See https://github.com/ucan-wg/delegation/blob/main/README.md#policy
	pol, err := policy.Build(
		policy.All(".to", policy.Like(".", "*@example.com")),
		policy.Equal(".from", "alice@example.com"),
	)
	if err != nil {
		panic(err)
	}

	err = policy.Match(pol, msg)
	// expect this policy to match the data
	if err != nil {
		panic("policy did not match")
	}

	// Alternatively you can parse a DAG-JSON encoded policy:
	pol, err = policy.Parse(`[
		["all", ".to", ["like", ".", "*@example.com"]],
		["==", ".from", "alice@example.com"]
	]`)
	if err != nil {
		panic(err)
	}

	err = policy.Match(pol, msg)
	// expect this policy to match the data
	if err != nil {
		panic("policy did not match")
	}
}

// TestTypedPolicy authors the same shape of policy against generated field
// descriptors (see examples/types/fields). The selector paths and value types
// come from the MessageSendArguments struct, so a wrong-typed value or a
// mistyped path would be a compile error rather than a runtime mismatch.
func TestTypedPolicy(t *testing.T) {
	msg := ipld.Map{
		"to":      []string{"bob@example.com", "carol@example.com"},
		"subject": "Hello!",
		"message": "Hi there",
	}

	pol, err := policy.Build(
		// every recipient must be an example.com address
		policy.Each(fields.MessageSendArguments.To, func(addr policy.Selector[string]) []policy.StatementBuilderFunc {
			return []policy.StatementBuilderFunc{policy.Glob(addr, "*@example.com")}
		}),
		policy.Eq(fields.MessageSendArguments.Subject, "Hello!"),
	)
	if err != nil {
		panic(err)
	}

	if err := policy.Match(pol, msg); err != nil {
		panic("policy did not match")
	}
}
