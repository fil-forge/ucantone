# Varsig

An implementation of [Varsig](https://github.com/ChainAgnostic/varsig) in Golang.

## Usage

Typically you'll just need a common varsig header:

```go
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/fil-forge/ucantone/varsig"
	"github.com/fil-forge/ucantone/varsig/algorithm/ed25519"
	"github.com/fil-forge/ucantone/varsig/common"
	"github.com/fil-forge/ucantone/varsig/payload/dagcbor"
)

func main() {
	data, err := varsig.Encode(common.Ed25519DagCbor)
	if err != nil {
		panic(err)
	}

	fmt.Println(base64.RawStdEncoding.EncodeToString(data)) // NAHtAe0BE3E

	h, err := varsig.Decode(data)
	if err != nil {
		panic(err)
	}

	sigAlgo := h.SignatureAlgorithm().(ed25519.SignatureAlgorithm)

	fmt.Println("Signature Algorithm:")
	fmt.Printf("\tCode:\t0x%02x", sigAlgo.Code())          // Code:   0xed
	fmt.Printf("\tCurve:\t0x%02x", sigAlgo.Curve())        // Curve:  0xed
	fmt.Printf("\tHash:\t0x%02x", sigAlgo.HashAlgorithm()) // Hash:   0x13

	payloadEnc := h.PayloadEncoding().(dagcbor.PayloadEncoding)

	fmt.Println("Payload Encoing:")
	fmt.Printf("\tCode:\t0x%02x", payloadEnc.Code())       // Code:   0x71
}
```

## Terminology

In the Varsig spec, the [signature algorithm](https://github.com/ChainAgnostic/varsig#signature-algorithm) is specified by a prefix discriminant followed by fields required for that prefix. That leaves a semantic ambiguity: is a "signature algorithm" what the prefix selects, or what the entire set of values specifies? There doesn't seem to be a ubiquitous pair of precise terms for these. In this library, the two concepts are named this way:

* A *Signature Scheme* is what the prefix selects.
* A *Signature Algorithm* is a fully specified algorithm, consisting of a Signature Scheme and any values needed to configure it.

[ECDSA](https://en.wikipedia.org/wiki/ECDSA) is a Signature Scheme, as is [EdDSA](https://en.wikipedia.org/wiki/EdDSA). [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) is a Signature Algorithm (EdDSA using Curve25519 and SHA-512), as is [Ed448](https://en.wikipedia.org/wiki/EdDSA#Ed448) (EdDSA using Curve448 and SHAKE256).

## Contributing

Feel free to join in. All welcome. Please [open an issue](https://github.com/fil-forge/ucantone/issues)!

## License

Dual-licensed under [MIT OR Apache 2.0](../LICENSE.md)
