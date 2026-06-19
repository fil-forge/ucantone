package server_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/server"
	tdm "github.com/fil-forge/ucantone/testutil/datamodel"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/invocation"
)

// echo is the /example/echo command bound to the Go types of its arguments and
// result. Handlers and clients both derive their types from it.
var echo = binding.Bind[*tdm.TestObject, *tdm.TestObject2](command.MustParse("/example/echo"))

// ExampleNewRoute bundles commands with their handlers as [server.Route] values
// and registers them on a server in one place. Because a Route's command and
// handler come from the same binding, their argument and result types cannot
// drift apart. Collecting routes as values also lets independent subsystems
// each contribute their own and hand them to the server for registration.
func ExampleNewRoute() {
	// Each subsystem contributes routes; here, the echo command and a handler
	// that returns the argument bytes as a string.
	routes := []server.Route{
		echo.Route(func(req *binding.Request[*tdm.TestObject], res *binding.Response[*tdm.TestObject2]) error {
			args := req.Task().Arguments()
			return res.SetSuccess(&tdm.TestObject2{Str: string(args.Bytes)})
		}),
	}

	service, _ := ed25519.GenerateIssuer()
	srv := server.NewHTTP(service)
	for _, r := range routes {
		srv.Handle(r.Command, r.Handler)
	}

	// Drive the server in-process by using it as the client's HTTP transport.
	endpoint, _ := url.Parse("http://echo.example")
	c, _ := client.NewHTTP(endpoint, client.WithHTTPClient(&http.Client{Transport: srv}))

	// A client invokes the command with typed arguments and unpacks the typed
	// result from the receipt.
	alice, _ := ed25519.GenerateIssuer()
	inv, _ := echo.Invoke(alice, alice.DID(), &tdm.TestObject{Bytes: []byte("hi")}, invocation.WithAudience(service.DID()))
	resp, _ := c.Execute(execution.NewRequest(context.Background(), inv))

	out, _ := echo.Unpack(resp.Receipt())
	fmt.Println(out.Str)
	// Output: hi
}
