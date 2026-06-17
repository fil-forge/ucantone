package secp256k1

import (
	"crypto"
	"crypto/sha256"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1/verifier"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/varsig"
	"github.com/fil-forge/ucantone/varsig/algorithm/ecdsa"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

const Code = multicodec.Secp256k1Priv

var tagSize = varint.UvarintSize(uint64(Code))

const keySize = 32

var size = tagSize + keySize

func Generate() (Signer, error) {
	sk, err := secec.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating secp256k1 key: %w", err)
	}
	s := make(Signer, size)
	varint.PutUvarint(s, uint64(Code))
	copy(s[tagSize:], sk.Bytes())
	return s, nil
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
		return nil, fmt.Errorf("decoding multibase string: %w", err)
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
		return nil, fmt.Errorf("invalid length: %d wanted: %d", len(b), size)
	}
	skc, _, err := varint.FromUvarint(b)
	if err != nil {
		return nil, fmt.Errorf("reading private key uvarint: %w", err)
	}
	if skc != uint64(Code) {
		return nil, fmt.Errorf("invalid private key codec: %s [0x%02x], expected: %s [0x%02x]", multicodec.Code(skc), skc, Code, uint64(Code))
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
	varint.PutUvarint(s, uint64(Code))
	copy(s[tagSize:], b)
	return s, nil
}

type Signer []byte

var _ multikey.Signer = (Signer)(nil)

func (s Signer) SignatureAlgorithm() varsig.Algorithm {
	return ecdsa.Secp256k1
}

func (s Signer) Code() multicodec.Code {
	return Code
}

func (s Signer) PrivateKey() any {
	sk, _ := secec.NewPrivateKey(s[tagSize:])
	return sk
}

func (s Signer) PublicKey() any {
	return s.verifier().PublicKey()
}

func (s Signer) Verifier() ucan.Verifier {
	return s.verifier()
}

func (s Signer) verifier() multikey.Verifier {
	sk, _ := secec.NewPrivateKey(s[tagSize:])
	v, _ := verifier.FromRaw(sk.PublicKey().CompressedBytes())
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

func (s Signer) KeyDID() did.DID {
	return s.verifier().KeyDID()
}
