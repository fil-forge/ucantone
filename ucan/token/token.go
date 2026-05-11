package token

import (
	"bytes"
	"fmt"

	"github.com/fil-forge/ucantone/ucan"
)

func VerifySignature(tok ucan.Token, verifier ucan.Verifier) (bool, error) {
	sigPayload, err := tok.SigPayload()
	if err != nil {
		return false, fmt.Errorf("getting token signature payload: %w", err)
	}

	var sigBuf bytes.Buffer
	err = sigPayload.MarshalCBOR(&sigBuf)
	if err != nil {
		return false, fmt.Errorf("marshaling signature payload: %w", err)
	}

	return tok.Issuer().DID() == verifier.DID() && verifier.Verify(sigBuf.Bytes(), tok.Signature().Bytes()), nil
}
