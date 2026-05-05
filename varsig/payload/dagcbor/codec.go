package dagcbor

import (
	"fmt"

	"github.com/fil-forge/ucantone/varsig"
	varint "github.com/multiformats/go-varint"
)

const Code = 0x71

type PayloadEncoding struct{}

func init() {
	varsig.RegisterPayloadEncoding(NewCodec())
}

func New() PayloadEncoding {
	return PayloadEncoding{}
}

func (dc PayloadEncoding) Code() uint64 {
	return Code
}

type Codec struct{}

func NewCodec() Codec {
	return Codec{}
}

func (dcc Codec) Code() uint64 {
	return Code
}

func (dcc Codec) Encode() ([]byte, error) {
	return varint.ToUvarint(Code), nil
}

func (dcc Codec) Decode(input []byte) (PayloadEncoding, int, error) {
	code, n, err := varint.FromUvarint(input)
	if err != nil {
		return PayloadEncoding{}, 0, err
	}
	if code != Code {
		return PayloadEncoding{}, n, fmt.Errorf("payload encoding code is not dag-cbor: 0x%02x, expected: 0x%02x", code, Code)
	}
	return PayloadEncoding{}, n, nil
}
