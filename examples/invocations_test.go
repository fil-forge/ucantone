package examples

import (
	"fmt"
	"testing"

	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
)

func TestInvocations(t *testing.T) {
	// mailer is an email service that can send emails
	mailer, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	alice, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	// delegate alice capability to use the email service
	dlg, err := delegation.Delegate(
		mailer,          // issuer
		alice.DID(),     // audience (receiver)
		mailer.DID(),    // subject
		"/message/send", // command
	)
	if err != nil {
		panic(err)
	}

	inv, err := invocation.Invoke(
		alice,
		mailer.DID(),
		"/message/send",
		datamodel.Map{
			"from":    "alice@example.com",
			"to":      "bob@example.com",
			"message": "Hello Bob!",
		},
		invocation.WithProofs(dlg.Link()),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(inv.Link())

	// Now send the invocations to the mailer for execution. You'll need to also
	// send the delegation as proof. You may want to use a _container_ for this.
	// See `container_test.go` in this directory.
}
