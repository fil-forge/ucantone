package signature

import (
	"github.com/fil-forge/ucantone/varsig"
)

type Signature struct {
	header varsig.VarsigHeader[varsig.SignatureAlgorithm, varsig.PayloadEncoding]
	bytes  []byte
}

func NewSignature[S varsig.SignatureAlgorithm, P varsig.PayloadEncoding](header varsig.VarsigHeader[S, P], bytes []byte) *Signature {
	return &Signature{
		varsig.NewHeader[varsig.SignatureAlgorithm, varsig.PayloadEncoding](header.SignatureAlgorithm(), header.PayloadEncoding()),
		bytes,
	}
}

// Bytes implements ucan.Signature.
func (s *Signature) Bytes() []byte {
	return s.bytes
}

// Header implements ucan.Signature.
func (s *Signature) Header() varsig.VarsigHeader[varsig.SignatureAlgorithm, varsig.PayloadEncoding] {
	return s.header
}

// var _ ucan.Signature = (*Signature)(nil)
