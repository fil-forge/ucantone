package multikey

import (
	"context"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
)

// DeriveVerifier produces a [ucan.Verifier] from Multikey [did.VerificationMaterial].
func DeriveVerifier(_ context.Context, mat did.VerificationMaterial) (ucan.Verifier, error) {
	pkm, ok := mat[did.MultikeyPublicKeyMultibaseProp].(string)
	if !ok {
		return nil, fmt.Errorf("Multikey verification method missing %s", did.MultikeyPublicKeyMultibaseProp)
	}
	return Parse(pkm)
}

func DeriveVerificationMethod(id did.URL, v Verifier) did.VerificationMethod {
	return did.VerificationMethod{
		ID:       id,
		Type:     did.MultikeyVerificationMethodType,
		Material: did.GenericMap{did.MultikeyPublicKeyMultibaseProp: FormatVerifier(v)},
	}
}

// Decoder decodes multiformat-tagged public key bytes into a Verifier.
type Decoder func([]byte) (Verifier, error)

var decoders = map[multicodec.Code]Decoder{}

// Register registers a [Decoder] for a given Multicodec code. The code should
// be the Multicodec code tagged `key` in the multicodec table.
func Register(code multicodec.Code, d Decoder) {
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

	d, ok := decoders[multicodec.Code(keyTypeCode)]
	if !ok {
		return nil, fmt.Errorf("no decoder registered for key type code: %s [0x%02x]", multicodec.Code(keyTypeCode), keyTypeCode)
	}
	return d(bytes)
}

// Signer is a multikey signer. It contains the private key bytes and can sign
// with them.
type Signer interface {
	ucan.Signer

	Code() multicodec.Code

	// Bytes returns the private key bytes with multiformats prefix varint.
	Bytes() []byte

	// Raw returns the bytes of the private key without multiformats tags.
	Raw() []byte

	// PrivateKey returns the private key in whatever format the underlying
	// implementation uses. Where possible, this should be a type that
	// ["crypto/x509".MarshalPKCS8PrivateKey] supports.
	PrivateKey() any

	// PublicKey returns the public key in whatever format the underlying
	// implementation uses. Where possible, this should be a type that
	// ["crypto/x509".MarshalPKIXPublicKey] supports.
	PublicKey() any

	// KeyDID is a convenience for `Verifier().KeyDID()`.
	KeyDID() did.DID
}

// Issuer is a [ucan.Issuer] whose signer is specifically a multikey [Signer].
type Issuer interface {
	ucan.Principal
	Signer
	String() string
}

// Verifier is a multikey verifier. It contains the public key bytes and can
// verify signatures with them.
type Verifier interface {
	ucan.Verifier

	Code() multicodec.Code

	// Bytes returns the public key bytes with multiformats prefix varint.
	Bytes() []byte

	// Raw returns the bytes of the public key without multiformats tags.
	Raw() []byte

	// PublicKey returns the public key in whatever format the underlying
	// implementation uses. Where possible, this should be a type that
	// ["crypto/x509".MarshalPKIXPublicKey] supports.
	PublicKey() any

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
	return did.New(key.Method, FormatVerifier(v))
}

// KeyIssuer wraps a [Signer] to produce a [ucan.Issuer] using the signer's
// [KeyDID] as the issuer DID.
func KeyIssuer(s Signer) Issuer {
	return keyIssuer{s}
}

type keyIssuer struct{ Signer }

func (k keyIssuer) DID() did.DID { return k.KeyDID() }

func (k keyIssuer) String() string {
	return k.DID().String()
}

type issuer struct {
	did did.DID
	Signer
}

var _ ucan.Issuer = issuer{}

// NewIssuer creates a new multikey Issuer with the given DID and multikey
// signer. The two may be completely unrelated: creating a useful Issuer is the
// caller's responsibility.
func NewIssuer(did did.DID, signer Signer) issuer {
	return issuer{did: did, Signer: signer}
}

func (i issuer) DID() did.DID {
	return i.did
}

func (i issuer) String() string {
	return fmt.Sprintf("%s (key: %s)", i.did, i.Signer.Verifier().String())
}
