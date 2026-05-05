package ed25519

import (
	"github.com/fil-forge/ucantone/varsig"
	"github.com/fil-forge/ucantone/varsig/algorithm/eddsa"
)

const Code = 0xED
const Sha2_512 = 0x13

type SignatureAlgorithm = eddsa.SignatureAlgorithm

func init() {
	varsig.RegisterSignatureAlgorithm(NewCodec())
}

func New() SignatureAlgorithm {
	return eddsa.New(Code, Sha2_512)
}

type Codec = eddsa.Codec

func NewCodec() Codec {
	return eddsa.NewCodec(Code, Sha2_512)
}
