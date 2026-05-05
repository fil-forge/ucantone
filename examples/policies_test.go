package examples

import (
	"testing"

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

	ok, err := policy.Match(pol, msg)
	if err != nil {
		panic(err)
	}
	// expect this policy to match the data
	if ok != true {
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

	ok, err = policy.Match(pol, msg)
	if err != nil {
		panic(err)
	}
	// expect this policy to match the data
	if ok != true {
		panic("policy did not match")
	}
}
