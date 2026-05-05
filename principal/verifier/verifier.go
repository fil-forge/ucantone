package verifier

import (
	"fmt"
	"strings"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal"
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
