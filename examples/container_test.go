package examples

import (
	"fmt"
	"testing"

	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	"github.com/fil-forge/ucantone/ucan/invocation"
)

func TestContainer(t *testing.T) {
	// mailer is an email service that can send emails
	mailer, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	alice, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	// delegate alice capability to use the email service, but only allow sending
	// to example.com email addresses
	dlg, err := delegation.Delegate(
		mailer,
		alice,
		mailer,
		"/message/send",
		delegation.WithPolicyBuilder(
			policy.All(".to", policy.Like(".", "*.example.com")),
		),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Delegation:", dlg.Link())

	// invoke the capability
	inv, err := invocation.Invoke(
		alice,
		mailer,
		"/message/send",
		datamodel.Map{
			"to":      []string{"bob@example.com"},
			"subject": "Hello!",
			"message": "Hello Bob, How do you do?",
		},
		invocation.WithProofs(dlg.Link()),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Invocation:", inv.Link())

	ct := container.New(
		container.WithDelegations(dlg),
		container.WithInvocations(inv),
	)

	buf, err := container.Encode(container.Base64Gzip, ct)
	if err != nil {
		panic(err)
	}

	// you could put this in a HTTP header if you like!
	fmt.Println("X-Ucan-Container:", string(buf))

	ct2, err := container.Decode(buf)
	if err != nil {
		panic(err)
	}

	fmt.Println("Delegation:", ct2.Delegations()[0].Link())
	fmt.Println("Invocation:", ct2.Invocations()[0].Link())
}
