package examples

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/examples/types"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/verification/multikey/ed25519"
)

// echoCmd declares the /example/echo command once and binds it to the Go types
// of its arguments (A = *EchoArguments) and its result (O = *EchoArguments —
// echo returns what it was handed). Every step below derives its types from
// this single declaration, so a mismatched argument or result type is a compile
// error rather than a run-time surprise.
//
// Production code usually wraps this in a MustParse-style helper (see
// libforge's commands.MustParse) to panic on a malformed command at init.
var echoCmd = binding.Bind[*types.EchoArguments, *types.EchoArguments](command.MustParse("/example/echo"))

// TestBindingEndToEnd demonstrates the full lifecycle of a typed command
// [binding.Binding] — invoke, handle, and read the result — using the server
// itself as an in-process HTTP transport, so the invocation runs through the
// real encode/decode/handle/encode/decode cycle without binding a port.
func TestBindingEndToEnd(t *testing.T) {
	service, err := ed25519.GenerateIssuer()
	if err != nil {
		t.Fatal(err)
	}
	alice, err := ed25519.GenerateIssuer()
	if err != nil {
		t.Fatal(err)
	}

	// Server: register the handler. echoCmd.Handler ties the handler's argument
	// and result types to the command — a handler with the wrong *Request[A] or
	// *Response[O] type does not compile.
	srv := server.NewHTTP(service)
	srv.Handle(echoCmd.Command, echoCmd.Handler(
		func(req *binding.Request[*types.EchoArguments], res *binding.Response[*types.EchoArguments]) error {
			args := req.Task().Arguments() // arguments, already decoded and typed
			return res.SetSuccess(args)    // result, encoded into the receipt
		},
	))

	// Authority: the service delegates echo to alice.
	dlg, err := echoCmd.Delegate(service, alice.DID(), service.DID())
	if err != nil {
		t.Fatal(err)
	}

	// Client: construct the invocation with typed arguments.
	// Invoke takes the typed arguments; passing a value of any other type is a
	// compile error.
	inv, err := echoCmd.Invoke(
		alice,
		service.DID(),
		&types.EchoArguments{Message: "Hello, UCAN!"},
		invocation.WithProofs(dlg.Link()),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Wire a client that uses the server directly as its HTTP transport.
	endpoint, err := url.Parse("http://echo.example")
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.NewHTTP(endpoint, client.WithHTTPClient(&http.Client{Transport: srv}))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.Execute(execution.NewRequest(context.Background(), inv, execution.WithDelegations(dlg)))
	if err != nil {
		t.Fatal(err)
	}

	// Client: read the typed result back out of the receipt.
	// ReadResult decodes the receipt into the command's result type O. There is
	// no manual Unpack/UnmarshalCBOR and no type argument to restate — the type
	// is fixed by echoCmd. On a failure receipt it returns the decoded error.
	out, err := echoCmd.Unpack(resp.Receipt())
	if err != nil {
		t.Fatal(err)
	}

	if out.Message != "Hello, UCAN!" {
		t.Fatalf("echo round-trip mismatch: got %q", out.Message)
	}
	fmt.Printf("echo result: %q\n", out.Message)
}
