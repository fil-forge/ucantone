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
fmt.Println("DID:", principal)
```

```go
// generate a new ed25519 issuer
issuer, err := ed25519.GenerateIssuer()
fmt.Println("DID:", issuer.DID())

// this principal can sign
sig := issuer.Sign([]byte{1, 2, 3})
fmt.Printf("Signature: 0x%x\n", sig)

// and has a private key (use format utility to multibase base64pad encode)
fmt.Println("Private Key:", multikey.FormatSigner(issuer))

// which can be stored and decoded later...
issuer2, err := ed25519.Decode(issuer.Bytes())
```

#### Delegation

See examples in [delegations_test.go](./examples/delegations_test.go)

```go
dlg, err = delegation.Delegate(
  alice,                              // issuer
  bob,                                // audience (receiver)
  mailer,                             // subject
  command.MustParse("/message/send"), // command
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
  command.MustParse("/message/send"),
  datamodel.Map{
    "from":    "alice@example.com",
    "to":      "bob@example.com",
    "message": "Hello Bob!",
  },
  invocation.WithProofs(dlg.Link()),
)
```

#### Command definition

See examples in [command_definition_test.go](./examples/command_definition_test.go)

```go
// Note: must be CBOR marshalable
type MessageSendArguments struct {
	To      []string `cborgen:"to"`
	Message string `cborgen:"message"`
}

type MessageSendOK struct {
  Delivered bool `cborgen:"delivered"`
}

cmd := command.MustParse("/message/send")
messageSend := binding.Bind[*MessageSendArguments, *MessageSendOK](cmd)

// delegate the capability
dlg, err := messageSend.Delegate(mailer, alice, mailer)

// invoke the capability
invocation, err := messageSend.Invoke(
  alice,
  mailer,
  &MessageSendArguments{
    To: []string{"bob@example.com"},
    Message: "Hello Bob, How do you do?",
  }
  invocation.WithProofs(dlg.Link()),
)

// later, after execution:
ok, err := messageSend.Unpack(receipt)
fmt.Println(ok.Delivered)
```

#### Typed policies

Policies can be authored against generated field descriptors instead of raw jq
selector strings. A descriptor is generated from a command's argument struct
(see the `fieldgen` package), so the comparison value is type-checked against
the field and the selector path is derived from a real field — a wrong type or
a mistyped path is a compile error. The builders return the same statements as
the string-selector builders, so they drop straight into `policy.Build`.

See examples in [policies_test.go](./examples/policies_test.go)

```go
pol, err := policy.Build(
  // every recipient must be an example.com address
  policy.Each(fields.MessageSendArguments.To, func(addr policy.Selector[string]) []policy.StatementBuilderFunc {
    return []policy.StatementBuilderFunc{policy.Glob(addr, "*@example.com")}
  }),
  policy.Eq(fields.MessageSendArguments.Subject, "Hello!"),
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
echo, err := command.Parse("/example/echo")
serviceID, err := ed25519.GenerateIssuer()

ucanSrv := server.NewHTTP(serviceID)

// Register an echo handler that returns the invocation arguments as the result
ucanSrv.Handle(echo, func(req execution.Request, res execution.Response) error {
  return res.SetSuccess(req.Invocation().Arguments())
})

http.ListenAndServe(":3000", ucanSrv)
```

#### Client

See examples in [server_test.go](./examples/server_test.go)

```go
// delegate echo capability to alice
dlg, err := delegation.Delegate(serviceID, alice, serviceID, echo)

// invoke (exercise) the capability
inv, err := invocation.Invoke(
  alice,
  serviceID,
  echo,
  datamodel.Map{"message": "Hello, UCAN!"},
  invocation.WithProofs(dlg.Link()),
)

c, err := client.NewHTTP(serviceURL)

// create an execution request and send it to the service, passing the
// invocation and the delegation as proof we are authorized
req := execution.NewRequest(context.Background(), inv, execution.WithDelegations(dlg))
resp, err := c.Execute(req)

if out := resp.Receipt().Out(); out.IsOK() {
  ok, _ := out.Unpack()
  fmt.Printf("Echo response: %+v\n", ok)
} else {
  _, x := out.Unpack()
  fmt.Printf("Invocation failed: %v\n", x)
}
```

## Contributing

Feel free to join in. All welcome. Please [open an issue](https://github.com/fil-forge/ucantone/issues)!

## License

Dual-licensed under [MIT OR Apache 2.0](LICENSE.md)
