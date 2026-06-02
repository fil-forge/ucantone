package verifier

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/verification/multikey"
	"github.com/fil-forge/ucantone/verification/multikey/internal/multiformat"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

func init() {
	multikey.Register(Code, Decode)
}

// Code is the multicodec code for `secp256k1-pub`.
const Code = 0xe7

// var SignatureAlgorithm = varsig_secp256k1.New()

var publicTagSize = varint.UvarintSize(Code)

const keySize = 33

var size = publicTagSize + keySize

func ParseKeyDID(str string) (multikey.Verifier, error) {
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

func Format(verifier multikey.Verifier) string {
	return verifier.KeyDID().String()
}

func Decode(b []byte) (multikey.Verifier, error) {
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
	_, err = secec.NewPublicKey(b[publicTagSize:])
	if err != nil {
		return nil, fmt.Errorf("invalid public key bytes: %w", err)
	}
	v := make(Verifier, size)
	copy(v, b)
	return v, nil
}

func Encode(verifier Verifier) []byte {
	return verifier
}

// FromRaw takes raw secp256k1 compressed public key bytes and tags with the
// secp256k1 verifier multiformat code, returning a secp256k1 verifier.
func FromRaw(b []byte) (Verifier, error) {
	if len(b) != keySize {
		return nil, fmt.Errorf("invalid length: %d wanted: %d", len(b), keySize)
	}
	return Verifier(multiformat.TagWith(Code, b)), nil
}

type Verifier []byte

var _ multikey.Verifier = (Verifier)(nil)

func (v Verifier) Code() uint64 {
	return Code
}

func (v Verifier) Verify(msg []byte, sig []byte) bool {
	pk, err := secec.NewPublicKey(v[publicTagSize:])
	if err != nil {
		return false
	}
	hash := sha256.New()
	hash.Write(msg)
	return pk.Verify(
		hash.Sum(nil),
		sig,
		&secec.ECDSAOptions{
			Encoding:        secec.EncodingCompact,
			Hash:            crypto.SHA256,
			RejectMalleable: true,
		},
	)
}

func (v Verifier) String() string {
	return fmt.Sprintf("secp256k1 Verifier{key=%s}", multikey.FormatVerifier(v))
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

func (v Verifier) KeyDID() did.DID {
	return multikey.KeyDID(v)
}
