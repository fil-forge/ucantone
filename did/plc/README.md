# did:plc

An implementation of the [`did:plc`](https://web.plc.directory/spec/v0.1/did-plc) DID
method in Golang.

`did:plc` is a self-authenticating, cryptographically verifiable DID method used by the
[AT Protocol](https://atproto.com). A DID is created by signing a *genesis operation*; the
DID identifier is derived from the hash of that operation, so it cannot be forged. The
operation history is an append-only log hosted by a *directory* server (the canonical one
is [`https://plc.directory`](https://plc.directory)), and the DID can be rotated or
updated over time by signing further operations with one of its registered rotation keys.

This package provides:

- A [`Resolver`](./resolver.go) that fetches and parses the DID Document for a `did:plc`
  DID — it implements the shared `did.Resolver` interface.
- A [`DirectoryClient`](./client.go) that additionally fetches the last operation
  (`Last`), publishes operations (`Update`), and deactivates a DID (`Deactivate`).
- Operation builders (`NewOperation`, `NewOperationFromPrevious`, `NewTombstone`),
  signing (`New`, `SignOperation`, `SignTombstone`), and signature verification
  (`VerifyOperationSignature`, `VerifyTombstoneSignature`).

## Usage

### Resolving an existing PLC DID

Resolve a `did:plc` DID to its DID Document:

```go
package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
)

func main() {
	endpoint, _ := url.Parse("https://plc.directory")
	resolver, err := plc.NewResolver(*endpoint)
	if err != nil {
		panic(err)
	}

	d := did.MustParse("did:plc:ewvi7nxzyoun6zhxrhs64oiz")
	doc, err := resolver.Resolve(context.Background(), d)
	if err != nil {
		panic(err)
	}

	fmt.Println("ID:         ", doc.ID)          // did:plc:ewvi7nxzyoun6zhxrhs64oiz
	fmt.Println("AlsoKnownAs:", doc.AlsoKnownAs) // [at://atproto.com]
	for _, svc := range doc.Service {
		fmt.Println("Service:    ", svc)
	}
}
```

### Creating a new PLC DID

Generate a rotation key, build and sign a genesis operation with `New`, then publish it to
the directory. The DID is derived from the signed genesis operation:

```go
package main

import (
	"context"
	"net/url"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
)

func main() {
	// The rotation key controls the DID. Keep it secret and back it up — anyone
	// who holds it can rewrite the DID's history.
	signer, err := secp256k1.Generate()
	if err != nil {
		panic(err)
	}
	key := signer.KeyDID()

	d, genesis, err := plc.New(
		signer,
		plc.WithRotationKeys(key),
		plc.WithVerificationMethods(map[string]did.DID{"atproto": key}),
		plc.WithAlsoKnownAs("at://alice.example.com"),
		plc.WithServices(map[string]plc.Service{
			"atproto_pds": {
				Type:     "AtprotoPersonalDataServer",
				Endpoint: "https://pds.example.com",
			},
		}),
	)
	if err != nil {
		panic(err)
	}

	// Publish the genesis operation to register the DID.
	endpoint, _ := url.Parse("https://plc.directory")
	client, err := plc.NewDirectoryClient(*endpoint)
	if err != nil {
		panic(err)
	}
	if err := client.Update(context.Background(), d, genesis); err != nil {
		panic(err)
	}

	println(d.String()) // did:plc:...
}
```

### Updating a PLC DID

Fetch the last operation, derive a new operation from it (inheriting the previous state and
merging your changes), sign it with a registered rotation key, and publish it:

```go
package main

import (
	"context"
	"net/url"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
)

func update(signer secp256k1.Signer, d did.DID) error {
	endpoint, _ := url.Parse("https://plc.directory")
	client, err := plc.NewDirectoryClient(*endpoint)
	if err != nil {
		return err
	}
	ctx := context.Background()

	// Fetch the current head of the operation log.
	last, err := client.Last(ctx, d)
	if err != nil {
		return err
	}

	// Build an operation that updates the handle, carrying over everything else.
	op, err := plc.NewOperationFromPrevious(
		last,
		plc.WithAlsoKnownAs("at://alice.new.example.com"),
	)
	if err != nil {
		return err
	}

	// Sign with a rotation key and publish.
	signed, err := plc.SignOperation(signer, op)
	if err != nil {
		return err
	}
	return client.Update(ctx, d, signed)
}
```

### Rotating a rotation key

To replace a rotation key, add the new key and remove the outgoing one in a single
operation. The operation must be signed by a rotation key that is valid in the *previous*
operation, so it is signed by the outgoing key as it is being removed:

```go
package main

import (
	"context"
	"net/url"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
)

// rotateKey replaces current with a freshly generated rotation key and returns
// the new signer.
func rotateKey(current secp256k1.Signer, d did.DID) (secp256k1.Signer, error) {
	endpoint, _ := url.Parse("https://plc.directory")
	client, err := plc.NewDirectoryClient(*endpoint)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	// Generate the replacement rotation key.
	next, err := secp256k1.Generate()
	if err != nil {
		return nil, err
	}

	last, err := client.Last(ctx, d)
	if err != nil {
		return nil, err
	}

	// In a single operation, add the new rotation key and remove the old one.
	op, err := plc.NewOperationFromPrevious(
		last,
		plc.WithRotationKeys(next.KeyDID()),
		plc.WithoutRotationKeys(current.KeyDID()),
	)
	if err != nil {
		return nil, err
	}

	// Sign with the outgoing key — it is still valid in the previous operation,
	// which is what authorizes this change.
	signed, err := plc.SignOperation(current, op)
	if err != nil {
		return nil, err
	}
	if err := client.Update(ctx, d, signed); err != nil {
		return nil, err
	}
	return next, nil
}
```

To deactivate a DID, build a tombstone from the last operation, sign it, and publish it
with `Deactivate`:

```go
last, _ := client.Last(ctx, d)
tomb, _ := plc.NewTombstoneFromPrevious(last)
tombstone, _ := plc.SignTombstone(signer, tomb)
err := client.Deactivate(ctx, d, tombstone)
```

When a DID has been deactivated, `Last` returns a `*plc.DeactivatedDIDError` — use
`errors.As` to detect it and inspect the tombstone:

```go
var deactivated *plc.DeactivatedDIDError
if _, err := client.Last(ctx, d); errors.As(err, &deactivated) {
	// DID is deactivated; deactivated.Operation is the *SignedTombstone.
}
```

## Contributing

Feel free to join in. All welcome. Please [open an issue](https://github.com/fil-forge/ucantone/issues)!

## License

Dual-licensed under [MIT OR Apache 2.0](../../LICENSE.md)
