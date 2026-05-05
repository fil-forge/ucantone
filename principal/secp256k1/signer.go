package secp256k1

import (
	"crypto"
	"crypto/sha256"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal"
	"github.com/fil-forge/ucantone/principal/secp256k1/verifier"
	"github.com/fil-forge/ucantone/varsig"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

const Code = 0x1301

var SignatureAlgorithm = verifier.SignatureAlgorithm

var tagSize = varint.UvarintSize(Code)

const keySize = 32

var size = tagSize + keySize

func Generate() (Signer, error) {
	sk, err := secec.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating secp256k1 key: %w", err)
	}
	s := make(Signer, size)
	varint.PutUvarint(s, Code)
	copy(s[tagSize:], sk.Bytes())
	return s, nil
}

// Parse parses a multibase encoded string containing a secp256k1 signer
// multiformat varint (0x1301) +  byte secp256k1 raw scalar value.
func Parse(str string) (Signer, error) {
	_, bytes, err := multibase.Decode(str)
	if err != nil {
		return nil, fmt.Errorf("decoding multibase string: %w", err)
	}
	return Decode(bytes)
}

func Format(signer principal.Signer) string {
	s, _ := multibase.Encode(multibase.Base64pad, signer.Bytes())
	return s
}

// Decode decodes a buffer of a secp256k1 signer multiformat varint (0x1301) +
// 32 byte secp256k1 raw scalar value.
func Decode(b []byte) (Signer, error) {
	if len(b) != size {
		return nil, fmt.Errorf("invalid length: %d wanted: %d", len(b), size)
	}
	skc, _, err := varint.FromUvarint(b)
	if err != nil {
		return nil, fmt.Errorf("reading private key uvarint: %w", err)
	}
	if skc != Code {
		return nil, fmt.Errorf("invalid private key codec: 0x%02x, expected: 0x%02x", skc, Code)
	}
	_, err = secec.NewPrivateKey(b[tagSize:])
	if err != nil {
		return nil, fmt.Errorf("creating private key: %w", err)
	}
	s := make(Signer, size)
	copy(s, b)
	return s, nil
}

func Encode(signer Signer) []byte {
	return signer
}

// FromRaw takes raw 32 byte scalar value and tags with the secp256k1
// signer multiformat code, returning a secp256k1 signer.
func FromRaw(b []byte) (Signer, error) {
	if len(b) != keySize {
		return nil, fmt.Errorf("invalid length: %d wanted: %d", len(b), keySize)
	}
	s := make(Signer, size)
	varint.PutUvarint(s, Code)
	copy(s[tagSize:], b)
	return s, nil
}

type Signer []byte

var _ principal.Signer = (Signer)(nil)

func (s Signer) Code() uint64 {
	return Code
}

func (s Signer) SignatureAlgorithm() varsig.SignatureAlgorithm {
	return SignatureAlgorithm
}

func (s Signer) Verifier() principal.Verifier {
	sk, _ := secec.NewPrivateKey(s[tagSize:])
	v, _ := verifier.FromRaw(sk.PublicKey().CompressedBytes())
	return v
}

func (s Signer) DID() did.DID {
	return s.Verifier().DID()
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
	sk, _ := secec.NewPrivateKey(s[tagSize:])
	hash := sha256.New()
	hash.Write(msg)
	sig, _ := sk.Sign(
		secec.RFC6979SHA256(), // for deterministic signatures, per RFC6979
		hash.Sum(nil),
		&secec.ECDSAOptions{
			Encoding:   secec.EncodingCompact,
			Hash:       crypto.SHA256,
			SelfVerify: false,
		},
	)
	return sig
}
