package examples

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/examples/types"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/bindexec"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/validator/bindcap"
	"github.com/fil-forge/ucantone/validator/capability"
)

func TestServer(t *testing.T) {
	echoCapability, err := capability.New("/example/echo")
	if err != nil {
		panic(err)
	}

	serviceID, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	ucanSrv := server.NewHTTP(serviceID)

	// Register an echo handler that returns the invocation arguments as the result
	ucanSrv.Handle(echoCapability, func(req execution.Request, res execution.Response) error {
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

	alice, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	// Allow alice to invoke the echo capability
	dlg, err := echoCapability.Delegate(serviceID, alice, serviceID)
	if err != nil {
		panic(err)
	}

	inv, err := echoCapability.Invoke(
		alice,
		serviceID,
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

	resp, err := c.Execute(execution.NewRequest(context.Background(), inv, execution.WithProofs(dlg)))
	if err != nil {
		panic(err)
	}

	if out := resp.Receipt().Out(); out.IsOk() {
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
	echoCapability, err := bindcap.New[*types.EchoArguments]("/example/echo")
	if err != nil {
		panic(err)
	}

	serviceID, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	ucanSrv := server.NewHTTP(serviceID)

	// Register an echo handler that returns the invocation arguments as the result
	ucanSrv.Handle(echoCapability, bindexec.NewHandler(func(req *bindexec.Request[*types.EchoArguments], res *bindexec.Response[*types.EchoArguments]) error {
		task := req.Task()
		args := task.BindArguments()
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

	alice, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	// Allow alice to invoke the echo capability
	dlg, err := echoCapability.Delegate(serviceID, alice, serviceID)
	if err != nil {
		panic(err)
	}

	inv, err := echoCapability.Invoke(
		alice,
		serviceID,
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

	resp, err := c.Execute(execution.NewRequest(context.Background(), inv, execution.WithProofs(dlg)))
	if err != nil {
		panic(err)
	}

	if out := resp.Receipt().Out(); out.IsOk() {
		ok, _ := out.Unpack()
		args := types.EchoArguments{}
		if err := args.UnmarshalCBOR(bytes.NewReader(ok)); err != nil {
			panic(err)
		}
		fmt.Printf("Echo response: %+v\n", args)
	} else {
		_, errBytes := out.Unpack()
		fmt.Printf("Invocation failed: %v\n", testutil.ResultMap(t, errBytes))
	}

	err = httpSrv.Shutdown(context.Background())
	if err != nil {
		panic(err)
	}
}

// In tests, you don't have to spin up a HTTP server, you can send invocations
// directly to the UCAN server by using it as a [http.RoundTripper] in a custom
// HTTP client.
func TestServerRoundTripper(t *testing.T) {
	echoCapability, err := capability.New("/example/echo")
	if err != nil {
		panic(err)
	}

	serviceID, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	ucanSrv := server.NewHTTP(serviceID)

	// Register an echo handler that returns the invocation arguments as the result
	ucanSrv.Handle(echoCapability, func(req execution.Request, res execution.Response) error {
		args := testutil.ArgsMap(t, req.Invocation())
		fmt.Printf("Echo: %s\n", args["message"])
		return res.SetSuccess(args)
	})

	// unused dummy URL
	serviceURL, err := url.Parse("http://test.service.example.com")
	if err != nil {
		panic(err)
	}

	alice, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	// Allow alice to invoke the echo capability
	dlg, err := echoCapability.Delegate(serviceID, alice, serviceID)
	if err != nil {
		panic(err)
	}

	inv, err := echoCapability.Invoke(
		alice,
		serviceID,
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

	resp, err := c.Execute(execution.NewRequest(context.Background(), inv, execution.WithProofs(dlg)))
	if err != nil {
		panic(err)
	}

	if out := resp.Receipt().Out(); out.IsOk() {
		ok, _ := out.Unpack()
		fmt.Printf("Echo response: %+v\n", testutil.ResultMap(t, ok))
	} else {
		_, errBytes := out.Unpack()
		fmt.Printf("Invocation failed: %v\n", testutil.ResultMap(t, errBytes))
	}
}
