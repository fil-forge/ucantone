package secp256k1

import (
	"github.com/fil-forge/ucantone/varsig"
	"github.com/fil-forge/ucantone/varsig/algorithm/ecdsa"
)

const Code = 0xe7
const Sha2_256 = 0x12

type SignatureAlgorithm = ecdsa.SignatureAlgorithm

func init() {
	varsig.RegisterSignatureAlgorithm(NewCodec())
}

func New() SignatureAlgorithm {
	return ecdsa.New(Code, Sha2_256)
}

type Codec = ecdsa.Codec

func NewCodec() Codec {
	return ecdsa.NewCodec(Code, Sha2_256)
}
