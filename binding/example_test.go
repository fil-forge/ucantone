package binding_test

import (
	"context"
	"fmt"

	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/principal/ed25519"
	tdm "github.com/fil-forge/ucantone/testutil/datamodel"
	"github.com/fil-forge/ucantone/ucan/command"
)

// echo is the single declaration of the /example/echo command: its path bound
// to the Go type of the arguments it accepts (*tdm.TestObject) and the result
// it returns (*tdm.TestObject2). Invoke, Handler, and Unpack below all derive
// their types from echo, so a mismatched argument or result type is a compile
// error rather than a run-time surprise.
var echo = binding.Bind[*tdm.TestObject, *tdm.TestObject2](command.MustParse("/example/echo"))

// Example walks the full lifecycle of a typed command: a client invokes it with
// typed arguments, a server handles it and returns a typed result, and the
// client unpacks that result — all without hand-written encoding or decoding.
func Example() {
	client, _ := ed25519.Generate()
	service, _ := ed25519.Generate()

	// Client: invoke the command with typed arguments. Invoke encodes them into
	// a signed invocation addressed to the service.
	inv, _ := echo.Invoke(client, service.DID(), &tdm.TestObject{Bytes: []byte("hi")})

	// Server: a typed handler receives the decoded arguments and sets a typed
	// result. Handler adapts it to the untyped handler the server registers.
	handle := echo.Handler(func(req *binding.Request[*tdm.TestObject], res *binding.Response[*tdm.TestObject2]) error {
		args := req.Task().Arguments()
		return res.SetSuccess(&tdm.TestObject2{Str: string(args.Bytes)})
	})

	xreq := execution.NewRequest(context.Background(), inv)
	xres, _ := execution.NewResponse(inv.Task().Link(), execution.WithSigner(service))
	_ = handle(xreq, xres)

	// Client: unpack the typed result (OK) out of the receipt.
	out, _ := echo.Unpack(xres.Receipt())
	fmt.Println(out.Str)
	// Output: hi
}
