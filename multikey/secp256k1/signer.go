package secp256k1

import (
	"crypto"
	"crypto/sha256"
	"fmt"

	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
	"gitlab.com/yawning/secp256k1-voi/secec"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1/verifier"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/varsig"
	"github.com/fil-forge/ucantone/varsig/algorithm/ecdsa"
)

const Code = multicodec.Secp256k1Priv

var tagSize = varint.UvarintSize(uint64(Code))

const keySize = 32

var size = tagSize + keySize

func Generate() (Signer, error) {
	sk, err := secec.GenerateKey()
	if err != nil {
		return Signer{}, fmt.Errorf("generating secp256k1 key: %w", err)
	}
	return Signer{key: sk}, nil
}

func GenerateIssuer() (multikey.Issuer, error) {
	signer, err := Generate()
	if err != nil {
		return nil, fmt.Errorf("generating signer: %w", err)
	}
	return multikey.KeyIssuer(signer), nil
}

// Parse parses a multibase encoded string containing a secp256k1 signer
// multiformat varint (0x1301) + byte secp256k1 raw scalar value.
func Parse(str string) (Signer, error) {
	_, bytes, err := multibase.Decode(str)
	if err != nil {
		return Signer{}, fmt.Errorf("decoding multibase string: %w", err)
	}
	return Decode(bytes)
}

func Format(signer multikey.Signer) string {
	s, _ := multibase.Encode(multibase.Base64pad, signer.Bytes())
	return s
}

// Decode decodes a buffer of a secp256k1 signer multiformat varint (0x1301) +
// 32 byte secp256k1 raw scalar value.
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
	sk, err := secec.NewPrivateKey(b[tagSize:])
	if err != nil {
		return Signer{}, fmt.Errorf("creating private key: %w", err)
	}
	return Signer{key: sk}, nil
}

func Encode(signer Signer) []byte {
	return signer.Bytes()
}

// FromRaw takes raw 32 byte scalar value and tags with the secp256k1
// signer multiformat code, returning a secp256k1 signer.
func FromRaw(b []byte) (Signer, error) {
	if len(b) != keySize {
		return Signer{}, fmt.Errorf("invalid length: %d wanted: %d", len(b), keySize)
	}
	sk, err := secec.NewPrivateKey(b)
	if err != nil {
		return Signer{}, fmt.Errorf("creating private key: %w", err)
	}
	return Signer{key: sk}, nil
}

// Signer is a secp256k1 private key. The key is held in an unexported field so
// that reflection based formatting and serialization (e.g. json.Marshal)
// cannot leak it. Use [Signer.Bytes] or [Signer.Raw] for explicit access to
// the key material.
type Signer struct {
	key *secec.PrivateKey
}

var _ multikey.Signer = Signer{}
var _ fmt.Formatter = Signer{}

// String returns the signer's key DID. It deliberately never exposes the
// private key bytes, so that passing a Signer to fmt.* cannot leak them.
// A zero-value Signer formats as a placeholder instead of panicking.
func (s Signer) String() string {
	if s.key == nil {
		return "<invalid secp256k1 signer>"
	}
	return s.KeyDID().String()
}

// Format implements [fmt.Formatter] so that every fmt verb, including %#v and
// %d which bypass [fmt.Stringer] and print unexported fields via reflection,
// renders the [Signer.String] value instead of the private key bytes.
func (s Signer) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, s.String())
}

func (s Signer) SignatureAlgorithm() varsig.Algorithm {
	return ecdsa.Secp256k1
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

func (s Signer) Verifier() ucan.Verifier {
	return s.verifier()
}

func (s Signer) verifier() multikey.Verifier {
	v, err := verifier.FromRaw(s.key.PublicKey().CompressedBytes())
	if err != nil {
		panic(fmt.Errorf("deriving verifier from secp256k1 signer: %w", err))
	}
	return v
}

// Bytes returns the private key bytes with multiformat prefix varint.
func (s Signer) Bytes() []byte {
	b := make([]byte, size)
	varint.PutUvarint(b, uint64(Code))
	copy(b[tagSize:], s.key.Bytes())
	return b
}

// Raw encodes the bytes of the private key without multiformats tags.
func (s Signer) Raw() []byte {
	return s.key.Bytes()
}

func (s Signer) Sign(msg []byte) []byte {
	hash := sha256.New()
	hash.Write(msg)
	sig, err := s.key.Sign(
		secec.RFC6979SHA256(), // for deterministic signatures, per RFC6979
		hash.Sum(nil),
		&secec.ECDSAOptions{
			Encoding:   secec.EncodingCompact,
			Hash:       crypto.SHA256,
			SelfVerify: false,
		},
	)
	if err != nil {
		panic(fmt.Errorf("signing with secp256k1 signer: %w", err))
	}
	return sig
}

func (s Signer) KeyDID() did.DID {
	return s.verifier().KeyDID()
}
