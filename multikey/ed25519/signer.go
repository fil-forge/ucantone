package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519/verifier"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/varsig"
	"github.com/fil-forge/ucantone/varsig/algorithm/eddsa"
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
		return Signer{}, fmt.Errorf("generating Ed25519 key: %w", err)
	}
	return Signer{key: priv}, nil
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
		return Signer{}, fmt.Errorf("decoding multibase string: %w", err)
	}
	return Decode(bytes)
}

// Decode decodes a buffer of an ed25519 signer multiformat varint (0x1300) + 32
// byte ed25519 private key.
func Decode(b []byte) (Signer, error) {
	if len(b) != size {
		return Signer{}, fmt.Errorf("invalid length: %d wanted: %d", len(b), size)
	}

	skc, _, err := varint.FromUvarint(b)
	if err != nil {
		return Signer{}, fmt.Errorf("reading private key uvarint: %w", err)
	}
	if skc != uint64(Code) {
		return Signer{}, fmt.Errorf("invalid private key codec: %s [0x%02x], expected: %s [0x%02x]", multicodec.Code(skc), skc, Code, uint64(Code))
	}

	return Signer{key: ed25519.NewKeyFromSeed(b[tagSize:])}, nil
}

func Encode(signer Signer) []byte {
	return signer.Bytes()
}

// FromRaw takes raw 32 byte ed25519 private key bytes and tags with the ed25519
// signer multiformat code, returning an ed25519 signer.
func FromRaw(b []byte) (Signer, error) {
	if len(b) != ed25519.SeedSize {
		return Signer{}, fmt.Errorf("invalid length: %d wanted: %d", len(b), ed25519.SeedSize)
	}
	return Signer{key: ed25519.NewKeyFromSeed(b)}, nil
}

// Signer is an ed25519 private key. The key is held in an unexported field so
// that reflection based formatting and serialization (e.g. json.Marshal)
// cannot leak it. Use [Signer.Bytes] or [Signer.Raw] for explicit access to
// the key material.
type Signer struct {
	key ed25519.PrivateKey
}

var _ multikey.Signer = Signer{}
var _ fmt.Formatter = Signer{}

// String returns the signer's key DID. It deliberately never exposes the
// private key bytes, so that passing a Signer to fmt.* cannot leak them.
// A zero-value Signer formats as a placeholder instead of panicking.
func (s Signer) String() string {
	if len(s.key) != ed25519.PrivateKeySize {
		return "<invalid ed25519 signer>"
	}
	return s.KeyDID().String()
}

// Format implements [fmt.Formatter] so that every fmt verb, including %#v and
// %d which bypass [fmt.Stringer] and print unexported fields via reflection,
// renders the [Signer.String] value instead of the private key bytes.
func (s Signer) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, s.String())
}

func (s Signer) Code() multicodec.Code {
	return Code
}

func (s Signer) PrivateKey() any {
	return s.key
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
	v, err := verifier.FromRaw(s.key.Public().(ed25519.PublicKey))
	if err != nil {
		panic(fmt.Errorf("deriving verifier from ed25519 signer: %w", err))
	}
	return v
}

// Bytes returns the private key bytes with multiformat prefix varint.
func (s Signer) Bytes() []byte {
	b := make([]byte, size)
	varint.PutUvarint(b, uint64(Code))
	copy(b[tagSize:], s.key.Seed())
	return b
}

// Raw encodes the bytes of the private key without multiformats tags.
func (s Signer) Raw() []byte {
	return s.key.Seed()
}

func (s Signer) Sign(msg []byte) []byte {
	return ed25519.Sign(s.key, msg)
}

func (s Signer) KeyDID() did.DID {
	return s.verifier().KeyDID()
}
