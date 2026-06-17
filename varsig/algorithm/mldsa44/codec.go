package mldsa44

import (
	"fmt"

	"github.com/fil-forge/ucantone/varsig"
	varint "github.com/multiformats/go-varint"
)

// https://github.com/multiformats/multicodec/blob/6bd718d6cb68e6714dea92758d7654aa1f9974b3/table.csv#L181
const Code = 0x1210

func init() {
	varsig.RegisterSignatureAlgorithm(NewCodec())
}

// SignatureAlgorithm is the ML-DSA-44 post-quantum signature algorithm. It has
// no curve or hash sub-codes, so it is represented by a single segment.
type SignatureAlgorithm struct{}

func New() SignatureAlgorithm {
	return SignatureAlgorithm{}
}

func (sa SignatureAlgorithm) Code() uint64 {
	return Code
}

func (sa SignatureAlgorithm) Segments() []uint64 {
	return []uint64{Code}
}

// Codec is the ML-DSA-44 signature algorithm codec.
type Codec struct{}

func NewCodec() Codec {
	return Codec{}
}

func (sac Codec) Code() uint64 {
	return Code
}

func (sac Codec) Segments() []uint64 {
	return []uint64{Code}
}

func (sac Codec) Encode() ([]byte, error) {
	size := varint.UvarintSize(Code)
	out := make([]byte, size)
	varint.PutUvarint(out, Code)
	return out, nil
}

func (sac Codec) Decode(input []byte) (SignatureAlgorithm, int, error) {
	code, n, err := varint.FromUvarint(input)
	if err != nil {
		return SignatureAlgorithm{}, 0, err
	}
	if code != Code {
		return SignatureAlgorithm{}, n, fmt.Errorf("signature code is not ML-DSA-44: 0x%02x, expected: 0x%02x", code, Code)
	}
	offset := n
	return SignatureAlgorithm{}, offset, nil
}
