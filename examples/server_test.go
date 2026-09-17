package examples

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/examples/types"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"

	"github.com/fil-forge/ucantone/binding"
)

func TestServer(t *testing.T) {
	echo, err := command.Parse("/example/echo")
	if err != nil {
		panic(err)
	}

	serviceID, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}

	ucanSrv := server.NewHTTP(serviceID)

	// Register an echo handler that returns the invocation arguments as the result
	ucanSrv.Handle(echo, func(req execution.Request, res execution.Response) error {
		args := testutil.ArgsMap(t, req.Invocation())
		fmt.Printf("Echo: %s\n", args["message"])
		return res.SetSuccess(args)
	})

	// Start the server on a random available port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	httpSrv := http.Server{Handler: ucanSrv}

	go func() {
		err := httpSrv.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	serviceURL, err := url.Parse("http://" + listener.Addr().String())
	if err != nil {
		panic(err)
	}
	fmt.Printf("UCAN Server is running at %s\n", serviceURL.String())

	// Server is now running and can accept invocations!

	alice, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}

	// Allow alice to invoke the echo capability
	dlg, err := delegation.Delegate(serviceID, alice.DID(), serviceID.DID(), echo)
	if err != nil {
		panic(err)
	}

	inv, err := invocation.Invoke(
		alice,
		serviceID.DID(),
		echo,
		datamodel.Map{"message": "Hello, UCAN!"},
		invocation.WithProofs(dlg.Link()),
	)
	if err != nil {
		panic(err)
	}

	// create a client to send the invocation to the server
	c, err := client.NewHTTP(serviceURL)
	if err != nil {
		panic(err)
	}

	resp, err := c.Execute(execution.NewRequest(context.Background(), inv, execution.WithDelegations(dlg)))
	if err != nil {
		panic(err)
	}

	if out := resp.Receipt().Out(); out.IsOK() {
		ok, _ := out.Unpack()
		fmt.Printf("Echo response: %+v\n", testutil.ResultMap(t, ok))
	} else {
		_, errBytes := out.Unpack()
		fmt.Printf("Invocation failed: %v\n", testutil.ResultMap(t, errBytes))
	}

	err = httpSrv.Shutdown(context.Background())
	if err != nil {
		panic(err)
	}
}

func TestTypedServer(t *testing.T) {
	echo := binding.Bind[*types.EchoArguments, *types.EchoArguments](command.MustParse("/example/echo"))

	serviceID, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}

	ucanSrv := server.NewHTTP(serviceID)

	// Register an echo handler that returns the invocation arguments as the
	// result
	ucanSrv.Handle(echo.Command, binding.NewHandler(func(req *binding.Request[*types.EchoArguments], res *binding.Response[*types.EchoArguments]) error {
		task := req.Task()
		args := task.Arguments()
		fmt.Printf("Echo: %s\n", args.Message)
		return res.SetSuccess(args)
	}))

	// Start the server on a random available port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	httpSrv := http.Server{Handler: ucanSrv}

	go func() {
		err := httpSrv.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	serviceURL, err := url.Parse("http://" + listener.Addr().String())
	if err != nil {
		panic(err)
	}
	fmt.Printf("UCAN Server is running at %s\n", serviceURL.String())

	// Server is now running and can accept invocations!

	alice, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}

	// Allow alice to invoke the echo capability
	dlg, err := echo.Delegate(serviceID, alice.DID(), serviceID.DID())
	if err != nil {
		panic(err)
	}

	inv, err := echo.Invoke(
		alice,
		serviceID.DID(),
		&types.EchoArguments{Message: "Hello, UCAN!"},
		invocation.WithProofs(dlg.Link()),
	)
	if err != nil {
		panic(err)
	}

	// create a client to send the invocation to the server
	c, err := client.NewHTTP(serviceURL)
	if err != nil {
		panic(err)
	}

	resp, err := c.Execute(execution.NewRequest(context.Background(), inv, execution.WithDelegations(dlg)))
	if err != nil {
		panic(err)
	}

	ok, err := echo.Unpack(resp.Receipt())
	if err != nil {
		panic(err)
	}
	fmt.Printf("Echo response: %+v\n", ok)

	err = httpSrv.Shutdown(context.Background())
	if err != nil {
		panic(err)
	}
}

// In tests, you don't have to spin up a HTTP server, you can send invocations
// directly to the UCAN server by using it as a [http.RoundTripper] in a custom
// HTTP client.
func TestServerRoundTripper(t *testing.T) {
	echo, err := command.Parse("/example/echo")
	if err != nil {
		panic(err)
	}

	serviceID, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}

	ucanSrv := server.NewHTTP(serviceID)

	// Register an echo handler that returns the invocation arguments as the result
	ucanSrv.Handle(echo, func(req execution.Request, res execution.Response) error {
		args := testutil.ArgsMap(t, req.Invocation())
		fmt.Printf("Echo: %s\n", args["message"])
		return res.SetSuccess(args)
	})

	// unused dummy URL
	serviceURL, err := url.Parse("http://test.service.example.com")
	if err != nil {
		panic(err)
	}

	alice, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}

	// Allow alice to invoke the echo capability
	dlg, err := delegation.Delegate(serviceID, alice.DID(), serviceID.DID(), echo)
	if err != nil {
		panic(err)
	}

	inv, err := invocation.Invoke(
		alice,
		serviceID.DID(),
		echo,
		datamodel.Map{"message": "Hello, UCAN!"},
		invocation.WithProofs(dlg.Link()),
	)
	if err != nil {
		panic(err)
	}

	// Create a client to send the invocation _directly_ to the server, using a
	// custom HTTP client that uses the server as a [http.RoundTripper].
	c, err := client.NewHTTP(serviceURL, client.WithHTTPClient(&http.Client{
		Transport: ucanSrv,
	}))
	// Alternatively:
	// c := client.New(ucanSrv, transport.DefaultHTTPOutboundCodec)
	if err != nil {
		panic(err)
	}

	resp, err := c.Execute(execution.NewRequest(context.Background(), inv, execution.WithDelegations(dlg)))
	if err != nil {
		panic(err)
	}

	if out := resp.Receipt().Out(); out.IsOK() {
		ok, _ := out.Unpack()
		fmt.Printf("Echo response: %+v\n", testutil.ResultMap(t, ok))
	} else {
		_, errBytes := out.Unpack()
		fmt.Printf("Invocation failed: %v\n", testutil.ResultMap(t, errBytes))
	}
}

// Many invocations can be sent in one request. The server executes every
// invocation addressed to it and answers each with its own receipt, which the
// client looks up by the task it ran.
func TestBatchClient(t *testing.T) {
	echo := binding.Bind[*types.EchoArguments, *types.EchoArguments](command.MustParse("/example/echo"))

	serviceID, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}

	ucanSrv := server.NewHTTP(serviceID)
	ucanSrv.Handle(echo.Command, binding.NewHandler(func(req *binding.Request[*types.EchoArguments], res *binding.Response[*types.EchoArguments]) error {
		return res.SetSuccess(req.Task().Arguments())
	}))

	alice, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}

	dlg, err := echo.Delegate(serviceID, alice.DID(), serviceID.DID())
	if err != nil {
		panic(err)
	}

	var invs []ucan.Invocation
	for _, message := range []string{"Hello", "UCAN!"} {
		inv, err := echo.Invoke(
			alice,
			serviceID.DID(),
			&types.EchoArguments{Message: message},
			invocation.WithProofs(dlg.Link()),
		)
		if err != nil {
			panic(err)
		}
		invs = append(invs, inv)
	}

	// unused dummy URL: the client sends directly to the server, see
	// TestServerRoundTripper
	serviceURL, err := url.Parse("http://test.service.example.com")
	if err != nil {
		panic(err)
	}
	c, err := client.NewHTTP(serviceURL, client.WithHTTPClient(&http.Client{Transport: ucanSrv}))
	if err != nil {
		panic(err)
	}

	// send every invocation in one request, with the delegation proving all of
	// them are authorized
	res, err := c.ExecuteBatch(batch.NewRequest(context.Background(), invs, batch.WithDelegations(dlg)))
	if err != nil {
		panic(err)
	}

	// every invocation has a receipt, found by the task it ran
	for _, inv := range invs {
		rcpt, _ := res.Receipt(inv.Task().Link())
		ok, err := echo.Unpack(rcpt)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Echo response: %+v\n", ok)
	}
}
