package nonstandard

import (
	"fmt"

	"github.com/fil-forge/ucantone/varsig"
	varint "github.com/multiformats/go-varint"
)

const Code = 0xd000

func init() {
	varsig.RegisterAlgorithmScheme(varsig.AlgorithmSchemeDef{
		Code:    Code,
		Name:    "absentee",
		Decoder: Decode,
	})
}

// SignatureAlgorithm is a signing algorithm that is not a known standard, and
// thus requires interactive verification.
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

func (sa SignatureAlgorithm) Encode() ([]byte, error) {
	size := varint.UvarintSize(Code)
	out := make([]byte, size)
	varint.PutUvarint(out, Code)
	return out, nil
}

func Decode(input []byte) (varsig.Algorithm, int, error) {
	code, n, err := varint.FromUvarint(input)
	if err != nil {
		return nil, 0, err
	}
	if code != Code {
		return nil, n, fmt.Errorf("signature code is not Non-Standard: 0x%02x, expected: 0x%02x", code, Code)
	}
	offset := n
	return SignatureAlgorithm{}, offset, nil
}

var NonStandard = New()
