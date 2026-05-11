package verifier

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal"
	ed25519 "github.com/fil-forge/ucantone/principal/ed25519/verifier"
	secp256k1 "github.com/fil-forge/ucantone/principal/secp256k1/verifier"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
)

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
	if !strings.HasPrefix(key.DID().String(), "did:key:") {
		return nil, fmt.Errorf("verifier is not a did:key")
	}
	return &WrappedVerifier{id, key}, nil
}

func Format(verifier principal.Verifier) string {
	return verifier.DID().String()
}

func Parse(str string) (principal.Verifier, error) {
	if !strings.HasPrefix(str, did.KeyPrefix) {
		return nil, fmt.Errorf("must start with '%s'", did.KeyPrefix)
	}
	code, bytes, err := multibase.Decode(str[len(did.KeyPrefix):])
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

	switch keyTypeCode {
	case ed25519.Code:
		return ed25519.Decode(bytes)
	case secp256k1.Code:
		return secp256k1.Decode(bytes)
	default:
		return nil, fmt.Errorf("unsupported key type code: 0x%x", keyTypeCode)
	}
}
