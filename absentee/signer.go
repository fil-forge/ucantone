package absentee

import (
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/varsig"
	"github.com/fil-forge/ucantone/varsig/algorithm/nonstandard"
)

var SignatureAlgorithm = nonstandard.New()

// Issuer is a special type of issuer that produces an absent signature,
// which signals that verifier needs to verify authorization interactively.
type Issuer struct {
	id did.DID
}

var _ ucan.Issuer = Issuer{}

func (a Issuer) DID() did.DID {
	return a.id
}

func (a Issuer) String() string {
	return fmt.Sprintf("%s (absentee)", a.id)
}

func (a Issuer) Sign(msg []byte) []byte {
	return []byte{}
}

func (a Issuer) SignatureAlgorithm() varsig.Algorithm {
	return SignatureAlgorithm
}

func (a Issuer) Verifier() ucan.Verifier {
	panic("absentee issuer does not have a verifier")
}

// From creates a special type of issuer that produces an absent signature,
// which signals that verifier needs to verify authorization interactively.
func From(id did.DID) Issuer {
	return Issuer{id}
}
