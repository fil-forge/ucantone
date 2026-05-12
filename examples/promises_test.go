package examples

import (
	"fmt"
	"testing"

	"github.com/fil-forge/ucantone/examples/types"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/ucan/promise"
	"github.com/fil-forge/ucantone/validator/bindcap"
)

func TestPromises(t *testing.T) {
	// Mailer is an email service that can send emails
	mailer, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	alice, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	// A list of email addresses
	mailingList, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	// A delegation from the mailer to alice allowing her to send emails
	msgSendDlg, err := delegation.Delegate(mailer, alice, mailer, "/msg/send")
	if err != nil {
		panic(err)
	}

	// A delegation from the mailing list to alice allowing her to read the emails
	listEmailsDlg, err := delegation.Delegate(mailingList, alice, mailingList, "/emails/list")
	if err != nil {
		panic(err)
	}

	// Read the emails on the mailing list. The mailer stores the email listings
	// so the invocation audience is the mailer.
	readListInv, err := invocation.Invoke(
		alice,
		mailingList,
		"/emails/list",
		datamodel.Map{"limit": 100},
		invocation.WithAudience(mailer),
		invocation.WithProofs(listEmailsDlg.Link()),
	)
	if err != nil {
		panic(err)
	}

	// Send a test email to the list.
	// This invocation is blocked on the successful result of the  `/emails/list`
	// task above, due to the `await/ok` promise.
	msgSendInv, err := invocation.Invoke(
		alice,
		mailer,
		"/msg/send",
		datamodel.Map{
			"from":    "alice@example.com",
			"to":      datamodel.Map{"await/ok": readListInv.Task().Link()},
			"message": "test",
		},
		invocation.WithAudience(mailer),
		invocation.WithProofs(msgSendDlg.Link()),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(msgSendInv.Link())

	// Now send these invocations to the mailer for execution. You'll need to also
	// send the two delegations as proof. You may want to use a _container_ for
	// this. See `container_test.go` in this directory.
}

func TestTypedPromises(t *testing.T) {
	// Define a capability for sending emails
	msgSendCap, err := bindcap.New[*types.PromisedMsgSendArguments]("/msg/send")
	if err != nil {
		panic(err)
	}

	// Define a capability listing emails on a mailing list
	emailListCap, err := bindcap.New[*types.EmailsListArguments]("/emails/list")
	if err != nil {
		panic(err)
	}

	// Mailer is an email service that can send emails
	mailer, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	alice, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	// A list of email addresses
	mailingList, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	// A delegation from the mailer to alice allowing her to send emails
	msgSendDlg, err := msgSendCap.Delegate(mailer, alice, mailer)
	if err != nil {
		panic(err)
	}

	// A delegation from the mailing list to alice allowing her to read the emails
	listEmailsDlg, err := emailListCap.Delegate(mailingList, alice, mailingList)
	if err != nil {
		panic(err)
	}

	// Read the emails on the mailing list. The mailer stores the email listings
	// so the invocation audience is the mailer.
	readListInv, err := emailListCap.Invoke(
		alice,
		mailingList,
		&types.EmailsListArguments{
			Limit: uint64(100),
		},
		invocation.WithAudience(mailer),
		invocation.WithProofs(listEmailsDlg.Link()),
	)
	if err != nil {
		panic(err)
	}

	// Send a test email to the list.
	// This invocation is blocked on the successful result of the  `/emails/list`
	// task above, due to the `await/ok` promise.
	msgSendInv, err := msgSendCap.Invoke(
		alice,
		mailer,
		&types.PromisedMsgSendArguments{
			From:    "alice@example.com",
			To:      promise.AwaitOK{Task: readListInv.Task().Link()},
			Message: "test",
		},
		invocation.WithAudience(mailer),
		invocation.WithProofs(msgSendDlg.Link()),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(msgSendInv.Link())

	// Now send these invocations to the mailer for execution. You'll need to also
	// send the two delegations as proof. You may want to use a _container_ for
	// this. See `container_test.go` in this directory.
}
