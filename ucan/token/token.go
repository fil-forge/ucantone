package token

import (
	"github.com/fil-forge/ucantone/ucan"
)

// VerifySignature verifies the invocation's signature against the literal
// signed-payload bytes preserved on decode. No reconstruction of the signing
// payload from typed fields — verification operates on the exact bytes the
// issuer signed, per the UCAN spec.
func VerifySignature(tok ucan.Token, verifier ucan.Verifier) (bool, error) {
	if tok.Issuer() != verifier.DID() {
		return false, nil
	}
	return verifier.Verify(tok.SignedBytes(), tok.Signature().Bytes()), nil
}
