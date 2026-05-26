package signature

import (
	"github.com/fil-forge/ucantone/varsig"
)

type Signature struct {
	header varsig.VarsigHeader
	bytes  []byte
}

func NewSignature(header varsig.VarsigHeader, bytes []byte) *Signature {
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
func (s *Signature) Header() varsig.VarsigHeader {
	return s.header
}

// var _ ucan.Signature = (*Signature)(nil)
