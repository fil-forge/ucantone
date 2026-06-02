package multikey

import (
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/verification"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
)

func init() {
	verification.RegisterVerifierFactory(
		did.MultikeyVerificationMethodType,
		DeriveVerifier,
	)
}

// DeriveVerifier produces a [ucan.Verifier] from Multikey [did.VerificationMaterial].
func DeriveVerifier(mat did.VerificationMaterial) (ucan.Verifier, error) {
	pkm, ok := mat[did.MultikeyPublicKeyMultibase].(string)
	if !ok {
		return nil, fmt.Errorf("Multikey verification method missing %s", did.MultikeyPublicKeyMultibase)
	}
	return Parse(pkm)
}

// Decoder decodes multiformat-tagged public key bytes into a Verifier.
type Decoder func([]byte) (Verifier, error)

var decoders = map[uint64]Decoder{}

// Register registers a [Decoder] for a given Multicodec code. The code should
// be the Multicodec code tagged `key` in the multicodec table.
func Register(code uint64, d Decoder) {
	decoders[code] = d
}

// Parses a Multikey string into a Verifier.
func Parse(mk string) (Verifier, error) {
	_, bytes, err := multibase.Decode(mk)
	if err != nil {
		return nil, err
	}

	keyTypeCode, _, err := varint.FromUvarint(bytes)
	if err != nil {
		return nil, fmt.Errorf("reading uvarint: %w", err)
	}

	d, ok := decoders[keyTypeCode]
	if !ok {
		return nil, fmt.Errorf("no decoder registered for key type code: 0x%x", keyTypeCode)
	}
	return d(bytes)
}

// Signer is a multikey signer. It contains the private key bytes and can sign
// with them.
type Signer interface {
	ucan.Signer

	// Bytes returns the private key bytes with multiformats prefix varint.
	Bytes() []byte
	// Raw returns the bytes of the private key without multiformats tags.
	Raw() []byte

	// KeyDID is a convenience for `Verifier().KeyDID()`.
	KeyDID() did.DID
}

type Issuer interface {
	ucan.Principal
	Signer
}

// Verifier is a multikey verifier. It contains the public key bytes and can
// verify signatures with them.
type Verifier interface {
	ucan.Verifier

	// Bytes returns the public key bytes with multiformats prefix varint.
	Bytes() []byte

	// KeyDID returns the `did:key` DID corresponding to this Verifier's public
	// key (which is not necessarily the same DID as the issuer of a token this
	// Verifier can verify).
	KeyDID() did.DID
}

// Format formats a [multikey.Signer] into a multibase encoded string
// (Base64pad).
func FormatSigner(signer Signer) string {
	s, _ := multibase.Encode(multibase.Base64pad, signer.Bytes())
	return s
}

// Format formats a [multikey.Verifier] into a multibase encoded string (Base58BTC).
func FormatVerifier(verifier Verifier) string {
	s, _ := multibase.Encode(multibase.Base58BTC, verifier.Bytes())
	return s
}

// KeyDID returns the `did:key` DID corresponding to the given Verifier's public
// key. This may not be the same DID that is using this key in some particular
// context, but it's a DID that *can* use it, and is the only `did:key` DID that
// can use it. If this key was found on a `did:key` DID, then this is by
// definition the DID it was found on. If this key was found on, for example, a
// `did:web` DID, then this is not.
func KeyDID(v Verifier) did.DID {
	id, _ := did.Parse(key.Prefix + FormatVerifier(v))
	return id
}

// KeyIssuer wraps a [Signer] to produce a [ucan.Issuer] using the signer's
// [KeyDID] as the issuer DID.
func KeyIssuer(s Signer) Issuer {
	return keyIssuer{s}
}

type keyIssuer struct{ Signer }

func (k keyIssuer) DID() did.DID { return k.Signer.KeyDID() }
