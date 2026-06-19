package signature

import (
	"github.com/fil-forge/ucantone/varsig"
)

type Signature struct {
	header varsig.Varsig
	bytes  []byte
}

func NewSignature(header varsig.Varsig, bytes []byte) *Signature {
	return &Signature{
		header,
		bytes,
	}
}

// Bytes implements ucan.Signature.
func (s *Signature) Bytes() []byte {
	return s.bytes
}

// Header implements ucan.Signature.
func (s *Signature) Header() varsig.Varsig {
	return s.header
}

// var _ ucan.Signature = (*Signature)(nil)
