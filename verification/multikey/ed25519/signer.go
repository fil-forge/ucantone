package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/varsig"
	"github.com/fil-forge/ucantone/varsig/algorithm/eddsa"
	"github.com/fil-forge/ucantone/verification/multikey"
	"github.com/fil-forge/ucantone/verification/multikey/ed25519/verifier"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
)

const Code = multicodec.Ed25519Priv

var tagSize = varint.UvarintSize(uint64(Code))

// Go ed25519 private key size is private + public. Go refers to the private key
// bytes as the "seed".
const keySize = ed25519.SeedSize

var size = tagSize + keySize

func Generate() (Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}
	s := make(Signer, size)
	varint.PutUvarint(s, uint64(Code))
	copy(s[tagSize:], priv)
	return s, nil
}

func GenerateIssuer() (multikey.Issuer, error) {
	signer, err := Generate()
	if err != nil {
		return nil, fmt.Errorf("generating signer: %w", err)
	}
	return multikey.KeyIssuer(signer), nil
}

// Parse parses a multibase encoded string containing a ed25519 signer
// multiformat varint (0x1300) + 32 byte ed25519 private key
func Parse(str string) (Signer, error) {
	_, bytes, err := multibase.Decode(str)
	if err != nil {
		return nil, fmt.Errorf("decoding multibase string: %w", err)
	}
	return Decode(bytes)
}

// Decode decodes a buffer of an ed25519 signer multiformat varint (0x1300) + 32
// byte ed25519 private key.
func Decode(b []byte) (Signer, error) {
	if len(b) != size {
		return nil, fmt.Errorf("invalid length: %d wanted: %d", len(b), size)
	}

	skc, _, err := varint.FromUvarint(b)
	if err != nil {
		return nil, fmt.Errorf("reading private key uvarint: %w", err)
	}
	if skc != uint64(Code) {
		return nil, fmt.Errorf("invalid private key codec: %s [0x%02x], expected: %s [0x%02x]", multicodec.Code(skc), skc, Code, uint64(Code))
	}

	s := make(Signer, size)
	copy(s, b)

	return s, nil
}

func Encode(signer Signer) []byte {
	return signer.Bytes()
}

// FromRaw takes raw 32 byte ed25519 private key bytes and tags with the ed25519
// signer multiformat code, returning an ed25519 signer.
func FromRaw(b []byte) (Signer, error) {
	if len(b) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid length: %d wanted: %d", len(b), ed25519.SeedSize)
	}
	s := make(Signer, size)
	varint.PutUvarint(s, uint64(Code))
	copy(s[tagSize:size], b[:ed25519.SeedSize])
	return s, nil
}

type Signer []byte

var _ multikey.Signer = (Signer)(nil)

func (s Signer) Code() multicodec.Code {
	return Code
}

func (s Signer) PrivateKey() any {
	sk := ed25519.NewKeyFromSeed(s[tagSize:])
	return sk
}

func (s Signer) PublicKey() any {
	return s.verifier().PublicKey()
}

func (s Signer) SignatureAlgorithm() varsig.Algorithm {
	return eddsa.Ed25519
}

func (s Signer) Verifier() ucan.Verifier {
	return s.verifier()
}

func (s Signer) verifier() multikey.Verifier {
	sk := ed25519.NewKeyFromSeed(s[tagSize:])
	v, _ := verifier.FromRaw(sk.Public().(ed25519.PublicKey))
	return v
}

// Bytes returns the private key bytes with multiformat prefix varint.
func (s Signer) Bytes() []byte {
	return s
}

// Raw encodes the bytes of the private key without multiformats tags.
func (s Signer) Raw() []byte {
	pk := make([]byte, keySize)
	copy(pk, s[tagSize:size])
	return pk
}

func (s Signer) Sign(msg []byte) []byte {
	sk := ed25519.NewKeyFromSeed(s[tagSize:])
	return ed25519.Sign(sk, msg)
}

func (s Signer) KeyDID() did.DID {
	return s.verifier().KeyDID()
}
