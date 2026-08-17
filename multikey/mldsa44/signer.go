package mldsa44

import (
	"fmt"

	"filippo.io/mldsa"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/mldsa44/verifier"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/varsig"
	varsigmldsa "github.com/fil-forge/ucantone/varsig/algorithm/mldsa"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
)

// Code is the Multicodec code for `mldsa44-priv`. It is not (yet) present in the
// go-multicodec table, so it is spelled out here to keep `did:key` and signer
// encodings identical to those produced before the `multikey` restructuring.
//
// https://github.com/multiformats/multicodec/blob/6bd718d6cb68e6714dea92758d7654aa1f9974b3/table.csv#L224
const Code = multicodec.Code(0x131a)

var tagSize = varint.UvarintSize(uint64(Code))

// ML-DSA-44 private keys are derived from a 32 byte seed.
const keySize = mldsa.PrivateKeySize

var size = tagSize + keySize

func Generate() (Signer, error) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return nil, fmt.Errorf("generating ML-DSA-44 key: %w", err)
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

// Parse parses a multibase encoded string containing an ML-DSA-44 signer
// multiformat varint (0x131a) + 32 byte ML-DSA-44 private key seed.
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

// Decode decodes a buffer of an ML-DSA-44 signer multiformat varint (0x131a) +
// 32 byte ML-DSA-44 private key seed.
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

	if _, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), b[tagSize:]); err != nil {
		return nil, fmt.Errorf("creating private key: %w", err)
	}

	s := make(Signer, size)
	copy(s, b)

	return s, nil
}

func Encode(signer Signer) []byte {
	return signer.Bytes()
}

// FromRaw takes raw 32 byte ML-DSA-44 private key seed bytes and tags with the
// ML-DSA-44 signer multiformat code, returning an ML-DSA-44 signer.
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

func (s Signer) Code() multicodec.Code {
	return Code
}

func (s Signer) SignatureAlgorithm() varsig.Algorithm {
	return varsigmldsa.MLDSA44
}

func (s Signer) PrivateKey() any {
	sk, _ := mldsa.NewPrivateKey(mldsa.MLDSA44(), s[tagSize:])
	return sk
}

func (s Signer) PublicKey() any {
	return s.verifier().PublicKey()
}

func (s Signer) Verifier() ucan.Verifier {
	return s.verifier()
}

func (s Signer) verifier() multikey.Verifier {
	sk, _ := mldsa.NewPrivateKey(mldsa.MLDSA44(), s[tagSize:])
	v, _ := verifier.FromRaw(sk.PublicKey().Bytes())
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

// Sign produces a deterministic ML-DSA-44 signature over msg. Determinism means
// signing the same message with the same key always yields the same signature.
func (s Signer) Sign(msg []byte) []byte {
	sk, _ := mldsa.NewPrivateKey(mldsa.MLDSA44(), s[tagSize:])
	sig, _ := sk.SignDeterministic(msg, nil)
	return sig
}

func (s Signer) KeyDID() did.DID {
	return s.verifier().KeyDID()
}
