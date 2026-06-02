package verifier

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/verification/multikey"
	"github.com/fil-forge/ucantone/verification/multikey/internal/multiformat"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
)

func init() {
	multikey.Register(Code, Decode)
}

// Code is the multicodec code for `ed25519-pub`.
const Code = 0xed

// var SignatureAlgorithm = varsig_ed25519.New()

var publicTagSize = varint.UvarintSize(Code)

const keySize = ed25519.PublicKeySize

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
	v := make(Verifier, size)
	copy(v, b)
	return v, nil
}

func Encode(verifier Verifier) []byte {
	return verifier
}

// FromRaw takes raw ed25519 public key bytes and tags with the ed25519 verifier
// multiformat code, returning an ed25519 verifier.
func FromRaw(b []byte) (Verifier, error) {
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid length: %d wanted: %d", len(b), ed25519.PublicKeySize)
	}
	return Verifier(multiformat.TagWith(Code, b)), nil
}

type Verifier []byte

var _ multikey.Verifier = (Verifier)(nil)

func (v Verifier) Code() uint64 {
	return Code
}

func (v Verifier) Verify(msg []byte, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(v[publicTagSize:]), msg, sig)
}

func (v Verifier) String() string {
	return fmt.Sprintf("ed25519 Verifier{key=%s}", multikey.FormatVerifier(v))
}

// Bytes returns the public key bytes with multiformat prefix varint.
func (v Verifier) Bytes() []byte {
	return v
}

// Raw encodes the bytes of the public key without multiformats tags.
func (v Verifier) Raw() []byte {
	k := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(k, v[publicTagSize:])
	return k
}

func (v Verifier) KeyDID() did.DID {
	return multikey.KeyDID(v)
}
