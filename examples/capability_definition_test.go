package examples

import (
	"fmt"
	"testing"

	"github.com/fil-forge/ucantone/examples/types"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/validator/bindcap"
	"github.com/fil-forge/ucantone/validator/capability"
)

func TestCapabilityDefinition(t *testing.T) {
	messageSendCapability, err := capability.New(
		"/message/send",
	)
	if err != nil {
		panic(err)
	}

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
	dlg, err := messageSendCapability.Delegate(mailer, alice, mailer)
	if err != nil {
		panic(err)
	}

	args := ipld.Map{
		"to":      []string{"bob@example.com"},
		"subject": "Hello!",
		"message": "Hello Bob, How do you do?",
	}

	// invoke the capability
	invocation, err := messageSendCapability.Invoke(
		alice,
		mailer,
		args,
		invocation.WithProofs(dlg.Link()),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(invocation.Link())

	// Now, send the invocation to the service. You'll probably want to put the
	// invocation and delegation in a Container and send a HTTP request...
}

func TestTypedCapabilityDefinition(t *testing.T) {
	// Defining a capability with a arguments type is useful because you get a
	// typed Invoke method (see below).
	// i.e. the args parameter for this method is the type you define here.
	messageSendCapability, err := bindcap.New[*types.MessageSendArguments](
		"/message/send",
	)
	if err != nil {
		panic(err)
	}

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
	dlg, err := messageSendCapability.Delegate(mailer, alice, mailer)
	if err != nil {
		panic(err)
	}

	// invoke the capability
	invocation, err := messageSendCapability.Invoke(
		alice,
		mailer,
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
	fmt.Println(invocation.Link())

	// Now, send the invocation to the service. You'll probably want to put the
	// invocation and delegation in a Container and send a HTTP request...
}
