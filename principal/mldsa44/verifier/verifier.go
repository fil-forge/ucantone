package verifier

import (
	"errors"
	"fmt"

	"filippo.io/mldsa"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal"
	"github.com/fil-forge/ucantone/principal/multiformat"
	keyverifier "github.com/fil-forge/ucantone/principal/verifier"
	varsig_mldsa44 "github.com/fil-forge/ucantone/varsig/algorithm/mldsa44"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
)

func init() {
	keyverifier.Register(Code, func(b []byte) (principal.Verifier, error) {
		return Decode(b)
	})
}

const Code = 0x1210

var SignatureAlgorithm = varsig_mldsa44.New()

var publicTagSize = varint.UvarintSize(Code)

const keySize = mldsa.MLDSA44PublicKeySize

var size = publicTagSize + keySize

func Parse(str string) (Verifier, error) {
	did, err := did.Parse(str)
	if err != nil {
		return nil, fmt.Errorf("invalid DID: %w", err)
	}
	if did.Method() != "key" {
		return nil, fmt.Errorf("invalid DID method: %s, expected: key", did.Method())
	}
	code, bytes, err := multibase.Decode(did.Identifier())
	if err != nil {
		return nil, err
	}
	if code != multibase.Base58BTC {
		return nil, errors.New("not Base58BTC encoded")
	}
	return Decode(bytes)
}

func Format(verifier principal.Verifier) string {
	return verifier.DID().String()
}

func Decode(b []byte) (Verifier, error) {
	if len(b) != size {
		return nil, fmt.Errorf("invalid length: %d wanted: %d", len(b), size)
	}
	code, _, err := varint.FromUvarint(b)
	if err != nil {
		return nil, fmt.Errorf("reading uvarint: %w", err)
	}
	if code != Code {
		return nil, fmt.Errorf("invalid public key codec: 0x%02x, expected: 0x%02x", code, Code)
	}
	if _, err := mldsa.NewPublicKey(mldsa.MLDSA44(), b[publicTagSize:]); err != nil {
		return nil, fmt.Errorf("invalid public key bytes: %w", err)
	}
	v := make(Verifier, size)
	copy(v, b)
	return v, nil
}

func Encode(verifier Verifier) []byte {
	return verifier
}

// FromRaw takes raw ML-DSA-44 public key bytes and tags with the ML-DSA-44
// verifier multiformat code, returning an ML-DSA-44 verifier.
func FromRaw(b []byte) (Verifier, error) {
	if len(b) != keySize {
		return nil, fmt.Errorf("invalid length: %d wanted: %d", len(b), keySize)
	}
	return Verifier(multiformat.TagWith(Code, b)), nil
}

type Verifier []byte

var _ principal.Verifier = (Verifier)(nil)

func (v Verifier) Code() uint64 {
	return Code
}

func (v Verifier) Verify(msg []byte, sig []byte) bool {
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), v[publicTagSize:])
	if err != nil {
		return false
	}
	return mldsa.Verify(pk, msg, sig, nil) == nil
}

func (v Verifier) DID() did.DID {
	b58key, _ := multibase.Encode(multibase.Base58BTC, v)
	id, _ := did.Parse(did.KeyPrefix + b58key)
	return id
}

// Bytes returns the public key bytes with multiformat prefix varint.
func (v Verifier) Bytes() []byte {
	return v
}

// Raw encodes the bytes of the public key without multiformats tags.
func (v Verifier) Raw() []byte {
	k := make([]byte, keySize)
	copy(k, v[publicTagSize:])
	return k
}
