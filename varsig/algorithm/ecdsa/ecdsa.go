package ecdsa

import (
	"fmt"

	"github.com/fil-forge/ucantone/varsig/algorithm"
	"github.com/multiformats/go-multicodec"
	varint "github.com/multiformats/go-varint"
)

// Varsig discriminant for ECDSA signature algorithms. Note that these
// discriminants are not in the multicodec table. They're [defined directly by
// Varsig](https://github.com/ChainAgnostic/varsig#signature-algorithm).
const Code = 0xEC

type Algorithm struct {
	curve    multicodec.Code
	hashAlgo multicodec.Code
}

func New(curve multicodec.Code, hashAlgo multicodec.Code) Algorithm {
	return Algorithm{curve, hashAlgo}
}

func (alg Algorithm) Segments() []uint64 {
	return []uint64{Code, uint64(alg.curve), uint64(alg.hashAlgo)}
}

// Curve returns the multicodec code for the curve used in this algorithm.
func (alg Algorithm) Curve() multicodec.Code {
	return alg.curve
}

// HashAlgorithm returns the multicodec code for the hash algorithm used in this
// algorithm.
func (alg Algorithm) HashAlgorithm() multicodec.Code {
	return alg.hashAlgo
}

func (alg Algorithm) Encode() ([]byte, error) {
	size := varint.UvarintSize(Code)
	size += varint.UvarintSize(uint64(alg.curve))
	size += varint.UvarintSize(uint64(alg.hashAlgo))
	out := make([]byte, size)
	offset := varint.PutUvarint(out, Code)
	offset += varint.PutUvarint(out[offset:], uint64(alg.curve))
	varint.PutUvarint(out[offset:], uint64(alg.hashAlgo))
	return out, nil
}

func Decode(input []byte) (algorithm.Algorithm, int, error) {
	code, n, err := varint.FromUvarint(input)
	if err != nil {
		return nil, 0, err
	}
	if code != Code {
		return nil, n, fmt.Errorf("signature code is not Ecdsa: 0x%02x, expected: 0x%02x", code, Code)
	}
	offset := n

	curve, n, err := varint.FromUvarint(input[offset:])
	if err != nil {
		return nil, 0, err
	}
	curveCode := multicodec.Code(curve)
	if curveCode.Tag() != "key" {
		return nil, 0, fmt.Errorf("invalid curve code: 0x%02x (%s, '%s'), expected a multicodec with 'key' tag", curve, curveCode, curveCode.Tag())
	}
	offset += n

	hashAlgo, n, err := varint.FromUvarint(input[offset:])
	if err != nil {
		return nil, 0, err
	}
	hashAlgoCode := multicodec.Code(hashAlgo)
	if hashAlgoCode.Tag() != "multihash" {
		return nil, 0, fmt.Errorf("invalid hash algorithm code: 0x%02x (%s, '%s'), expected a multicodec with 'multihash' tag", hashAlgo, hashAlgoCode, hashAlgoCode.Tag())
	}
	offset += n

	return New(curveCode, hashAlgoCode), offset, nil
}

var Secp256k1 = New(multicodec.Secp256k1Pub, multicodec.Sha2_256)
