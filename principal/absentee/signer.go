package absentee

import (
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/varsig"
	"github.com/fil-forge/ucantone/varsig/algorithm/nonstandard"
)

var SignatureAlgorithm = nonstandard.New()

// Signer is a special type of signer that produces an absent signature,
// which signals that verifier needs to verify authorization interactively.
type Signer struct {
	id did.DID
}

var _ ucan.Signer = Signer{}

func (a Signer) DID() did.DID {
	return a.id
}

func (a Signer) Sign(msg []byte) []byte {
	return []byte{}
}

func (a Signer) SignatureAlgorithm() varsig.SignatureAlgorithm {
	return SignatureAlgorithm
}

// From creates a special type of signer that produces an absent signature,
// which signals that verifier needs to verify authorization interactively.
func From(id did.DID) Signer {
	return Signer{id}
}
