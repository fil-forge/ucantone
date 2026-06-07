package verification

import (
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
)

type issuer struct {
	did did.DID
	ucan.Signer
}

var _ ucan.Issuer = issuer{}

// NewIssuer creates a new issuer with the given DID and signer. The two may be
// completely unrelated: creating a useful Issuer is the caller's
// responsibility.
func NewIssuer(did did.DID, signer ucan.Signer) issuer {
	return issuer{did: did, Signer: signer}
}

func (i issuer) DID() did.DID {
	return i.did
}

func (i issuer) String() string {
	return fmt.Sprintf("%s (key: %s)", i.did, i.Signer.Verifier().String())
}
