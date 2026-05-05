<div align="center">
  <a href="https://github.com/fil-forge/ucantone" target="_blank">
    <img src="https://github.com/user-attachments/assets/4f541813-b946-4dbc-a170-709b6ae4f05e" alt="ucantone logo" height="250" />
  </a>
  <h1 align="center">ucantone</h1>
  <p align="center">Ucanto for UCAN 1.0.</p>
</div>

## Usage

### API Reference

[pkg.go.dev/github.com/fil-forge/ucantone](https://pkg.go.dev/github.com/fil-forge/ucantone)

### Examples

#### Principals

See examples in [principals_test.go](./examples/principals_test.go)

```go
principal, err := did.Parse("did:key:z6MkfBSb2hC6g3UGnqNmWfmGvPdfMorBpT2osm9bk9b4Cyqu")
fmt.Println("DID:", principal.DID())
```

```go
// generate a new ed25519 signer (it is also a principal - has a DID() method)
signerPrincipal, err := ed25519.Generate()
fmt.Println("DID:", signerPrincipal.DID())

// this principal can sign
sig := signerPrincipal.Sign([]byte{1, 2, 3})
fmt.Printf("Signature: 0x%x\n", sig)

// and has a private key (use format utility to multibase base64pad encode)
fmt.Println("Private Key:", signer.Format(signerPrincipal))

// which can be stored and decoded later...
signerPrincipal2, err := ed25519.Decode(signerPrincipal.Bytes())
```

#### Delegation

See examples in [delegations_test.go](./examples/delegations_test.go)

```go
dlg, err = delegation.Delegate(
  alice,           // issuer
  bob,             // audience (receiver)
  mailer,          // subject
  "/message/send", // command
  // policy (alice delegates bob capability to use the email service, but only
  // allows bob to send to example.com email addresses)
  delegation.WithPolicyBuilder(
    policy.All(".to", policy.Like(".", "*@example.com")),
  ),
)
```

#### Invocation

See examples in [invocations_test.go](./examples/invocations_test.go)

```go
inv, err := invocation.Invoke(
  alice,
  mailer,
  "/message/send",
  ipld.Map{
    "from":    "alice@example.com",
    "to":      "bob@example.com",
    "message": "Hello Bob!",
  },
  invocation.WithProofs(dlg.Link()),
)
```

#### Capability definition

See examples in [capability_definition_test.go](./examples/capability_definition_test.go)

```go
type MessageSendArguments struct {
	To      []string
	Message string
}

messageSend, err := capability.New(
  "/message/send",
  capability.WithPolicyBuilder(
    policy.NotEqual(".to", []string{}),
  ),
)

// delegate the capability
dlg, err := messageSend.Delegate(mailer, alice, mailer)

// invoke the capability
invocation, err := messageSend.Invoke(
  alice,
  mailer,
  ipld.Map{
		"to":      []string{"bob@example.com"},
		"subject": "Hello!",
		"message": "Hello Bob, How do you do?",
	},
  invocation.WithProofs(dlg.Link()),
)
```

#### Container

See examples in [container_test.go](./examples/container_test.go)

```go
ct := container.New(
  container.WithDelegations(dlg0, dlg1),
  container.WithInvocations(inv0),
  // container.WithReceipts(...),
)

// Various encoding options are available, the following (Base64Gzip) is good
// for when you want to add the container to a HTTP header.
buf, err := container.Encode(container.Base64Gzip, ct)
```

#### Server

See examples in [server_test.go](./examples/server_test.go)

```go
echoCapability, err := capability.New("/example/echo")
serviceID, err := ed25519.Generate()

ucanSrv := server.NewHTTP(serviceID)

// Register an echo handler that returns the invocation arguments as the result
ucanSrv.Handle(echoCapability, func(req execution.Request, res execution.Response) error {
  return res.SetSuccess(req.Invocation().Arguments())
})

http.ListenAndServe(":3000", ucanSrv)
```

#### Client

See examples in [server_test.go](./examples/server_test.go)

```go
// delegate echo capability to alice
dlg, err := echoCapability.Delegate(serviceID, alice, serviceID)

// invoke (exercise) the capability
inv, err := echoCapability.Invoke(
  alice,
  serviceID,
  ipld.Map{"message": "Hello, UCAN!"},
  invocation.WithProofs(dlg.Link()),
)

c, err := client.NewHTTP(serviceURL)

// create an execution request and send it to the service, passing the
// invocation and the delegation as proof we are authorized
req := execution.NewRequest(context.Background(), inv, execution.WithProofs(dlg))
resp, err := c.Execute(req)

o, x := result.Unwrap(resp.Receipt().Out())
if x != nil {
  fmt.Printf("Invocation failed: %v\n", x)
} else {
  fmt.Printf("Echo response: %+v\n", o)
}
```

## Contributing

Feel free to join in. All welcome. Please [open an issue](https://github.com/fil-forge/ucantone/issues)!

## License

Dual-licensed under [MIT OR Apache 2.0](LICENSE.md)
