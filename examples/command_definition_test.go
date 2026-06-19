package examples

import (
	"fmt"
	"testing"

	"github.com/fil-forge/ucantone/examples/types"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"

	"github.com/fil-forge/ucantone/binding"
)

func TestCommandDefinition(t *testing.T) {
	messageSend, err := command.Parse("/message/send")
	if err != nil {
		panic(err)
	}

	// mailer is an email service that can send emails
	mailer, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}

	alice, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}

	// delegate alice capability to use the email service
	dlg, err := delegation.Delegate(mailer, alice.DID(), mailer.DID(), messageSend)
	if err != nil {
		panic(err)
	}

	args := datamodel.Map{
		"to":      []string{"bob@example.com"},
		"subject": "Hello!",
		"message": "Hello Bob, How do you do?",
	}

	// invoke the command
	inv, err := invocation.Invoke(
		alice,
		mailer.DID(),
		messageSend,
		args,
		invocation.WithProofs(dlg.Link()),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(inv.Link())

	// Now, send the invocation to the service. You'll probably want to put the
	// invocation and delegation in a Container and send a HTTP request...
}

func TestTypedCommandDefinition(t *testing.T) {
	// Defining a command with a arguments type is useful because you get an
	// Invoke method with a typed arguments parameter and an Unpack method for
	// unpacking the typed return value from an invocation receipt.
	messageSend := binding.Bind[*types.MessageSendArguments, *datamodel.Map](command.MustParse("/message/send"))

	// mailer is an email service that can send emails
	mailer, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}

	alice, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}

	// delegate alice capability to use the email service
	dlg, err := messageSend.Delegate(mailer, alice.DID(), mailer.DID())
	if err != nil {
		panic(err)
	}

	// invoke the command
	inv, err := messageSend.Invoke(
		alice,
		mailer.DID(),
		&types.MessageSendArguments{
			To:      []string{"bob@example.com"},
			Subject: "Hello!",
			Message: "Hello Bob, How do you do?",
		},
		invocation.WithProofs(dlg.Link()),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(inv.Link())

	// Now, send the invocation to the service. You'll probably want to put the
	// invocation and delegation in a Container and send a HTTP request...
}
