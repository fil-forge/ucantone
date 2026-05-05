package principal

import (
	"github.com/fil-forge/ucantone/ucan"
)

// Signer is the principal that can issue UCANs (and sign payloads). While it's
// primary role is to sign payloads it also provides a `Verifier` interface so
// it can be used for verifying signed payloads as well.
type Signer interface {
	ucan.Signer
	Code() uint64
	Verifier() Verifier
	// Bytes returns the private key bytes with multiformats prefix varint.
	Bytes() []byte
	// Raw encodes the bytes of the private key without multiformats tags.
	Raw() []byte
}

// Verifier is the principal that issued a UCAN. In usually represents remote
// principal and is used to verify that certain payloads were signed by it.
type Verifier interface {
	ucan.Verifier
	Code() uint64
	// Bytes returns the public key bytes with multiformats prefix varint.
	Bytes() []byte
	// Raw encodes the bytes of the public key without multiformats tags.
	Raw() []byte
}
