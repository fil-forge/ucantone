package verifier

import (
	"errors"
	"fmt"

	"filippo.io/mldsa"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/internal/multiformat"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
)

func init() {
	multikey.Register(Code, Decode)
}

// Code is the Multicodec code for `mldsa44-pub`. It is not (yet) present in the
// go-multicodec table, so it is spelled out here to keep `did:key` encodings
// identical to those produced before the `multikey` restructuring.
//
// https://github.com/multiformats/multicodec/blob/6bd718d6cb68e6714dea92758d7654aa1f9974b3/table.csv#L181
const Code = multicodec.Code(0x1210)

var publicTagSize = varint.UvarintSize(uint64(Code))

const keySize = mldsa.MLDSA44PublicKeySize

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
	if code != uint64(Code) {
		return nil, fmt.Errorf("invalid public key codec: %s [0x%02x], expected: %s [0x%02x]", multicodec.Code(code), code, Code, uint64(Code))
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

var _ multikey.Verifier = (Verifier)(nil)

func (v Verifier) Code() multicodec.Code {
	return Code
}

func (v Verifier) PublicKey() any {
	pk, _ := mldsa.NewPublicKey(mldsa.MLDSA44(), v[publicTagSize:])
	return pk
}

func (v Verifier) Verify(msg []byte, sig []byte) bool {
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), v[publicTagSize:])
	if err != nil {
		return false
	}
	return mldsa.Verify(pk, msg, sig, nil) == nil
}

func (v Verifier) String() string {
	return multikey.FormatVerifier(v)
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
