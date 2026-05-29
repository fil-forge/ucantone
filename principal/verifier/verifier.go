package verifier

import (
	"errors"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
)

// Decoder decodes multiformat-tagged public key bytes into a Verifier.
type Decoder func([]byte) (principal.Verifier, error)

var decoders = map[uint64]Decoder{}

func Register(code uint64, d Decoder) {
	decoders[code] = d
}

type Unwrapper interface {
	// Unwrap returns the unwrapped did:key of this signer.
	Unwrap() principal.Verifier
}

type WrappedVerifier struct {
	id  did.DID
	key principal.Verifier
}

func (w *WrappedVerifier) Code() uint64 {
	return w.key.Code()
}

func (w *WrappedVerifier) DID() did.DID {
	return w.id
}

func (w *WrappedVerifier) Bytes() []byte {
	return w.key.Bytes()
}

func (w *WrappedVerifier) Raw() []byte {
	return w.key.Raw()
}

func (w *WrappedVerifier) Verify(msg []byte, sig []byte) bool {
	return w.key.Verify(msg, sig)
}

func (w *WrappedVerifier) Unwrap() principal.Verifier {
	return w.key
}

// Wrap the key of this verifier into a verifier with a different DID. This is
// primarily used to wrap a did:key verifier with a verifier that has a DID of
// a different method.
func Wrap(key principal.Verifier, id did.DID) (*WrappedVerifier, error) {
	if key.DID().Method() != "key" {
		return nil, fmt.Errorf("verifier is not a did:key")
	}
	return &WrappedVerifier{id, key}, nil
}

func Format(verifier principal.Verifier) string {
	return verifier.DID().String()
}

// Parse parses a string into a Verifier. The string must be a valid did:key
// DID. An appropriate decoder should be registered in advance with [Register]
// for the key type code.
func Parse(s string) (principal.Verifier, error) {
	did, err := did.Parse(s)
	if err != nil {
		return nil, err
	}
	return FromDIDKey(did)
}

// FromDIDKey decodes a did:key DID into a Verifier. An appropriate decoder
// should be registered in advance with [Register] for the key type code.
// Returns an error if the DID is not a did:key, if the did:key is malformed, or
// if there is no decoder registered for the key type code.
func FromDIDKey(did did.DID) (principal.Verifier, error) {
	if did.Method() != "key" {
		return nil, fmt.Errorf("unsupported DID method: %s", did.Method())
	}

	return FromMultikey(did.Identifier())
}

func FromMultikey(mk string) (principal.Verifier, error) {
	code, bytes, err := multibase.Decode(mk)
	if err != nil {
		return nil, err
	}
	if code != multibase.Base58BTC {
		return nil, errors.New("not Base58BTC encoded")
	}

	keyTypeCode, _, err := varint.FromUvarint(bytes)
	if err != nil {
		return nil, fmt.Errorf("reading uvarint: %w", err)
	}

	d, ok := decoders[keyTypeCode]
	if !ok {
		return nil, fmt.Errorf("no decoder registered for key type code: 0x%x", keyTypeCode)
	}
	return d(bytes)
}
