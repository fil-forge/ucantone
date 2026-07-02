package mldsa

import (
	"fmt"

	"github.com/fil-forge/ucantone/varsig"
	varint "github.com/multiformats/go-varint"
)

// Code is the Varsig discriminant for the ML-DSA-44 post-quantum signature
// algorithm. Unlike ECDSA and EdDSA, ML-DSA is a self-contained scheme with no
// curve or hash sub-codes, so it is identified by a single segment. The
// discriminant reuses the ML-DSA-44 public key Multicodec code so that the wire
// encoding matches deployments produced before the `multikey` restructuring.
//
// https://github.com/multiformats/multicodec/blob/6bd718d6cb68e6714dea92758d7654aa1f9974b3/table.csv#L181
const Code = 0x1210

func init() {
	// ML-DSA-44 is not one of Varsig's spec-defined algorithms, so it registers
	// itself the way the other add-on algorithms do (see the `nonstandard`
	// package) rather than being wired in centrally from `varsig`.
	varsig.RegisterAlgorithmScheme(varsig.AlgorithmSchemeDef{
		Code:    Code,
		Name:    "ML-DSA-44",
		Decoder: Decode,
	})
}

// Algorithm is the ML-DSA-44 post-quantum signature algorithm. It carries no
// curve or hash sub-codes, so it is represented by a single segment.
type Algorithm struct{}

// New returns the ML-DSA-44 signature algorithm.
func New() Algorithm {
	return Algorithm{}
}

// Code returns the Varsig discriminant for ML-DSA-44.
func (alg Algorithm) Code() uint64 {
	return Code
}

// Segments returns the sequence of varints that make up this algorithm's
// portion of a Varsig header. ML-DSA-44 has no sub-codes, so this is a single
// segment.
func (alg Algorithm) Segments() []uint64 {
	return []uint64{Code}
}

// Encode encodes the ML-DSA-44 signature algorithm as a varint segment.
func (alg Algorithm) Encode() ([]byte, error) {
	size := varint.UvarintSize(Code)
	out := make([]byte, size)
	varint.PutUvarint(out, Code)
	return out, nil
}

// Decode decodes an ML-DSA-44 signature algorithm segment, returning the
// algorithm and the number of bytes consumed.
func Decode(input []byte) (varsig.Algorithm, int, error) {
	code, n, err := varint.FromUvarint(input)
	if err != nil {
		return nil, 0, err
	}
	if code != Code {
		return nil, n, fmt.Errorf("signature code is not ML-DSA-44: 0x%02x, expected: 0x%02x", code, Code)
	}
	offset := n
	return Algorithm{}, offset, nil
}

// MLDSA44 is the ML-DSA-44 signature algorithm, mirroring [eddsa.Ed25519] and
// [ecdsa.Secp256k1].
var MLDSA44 = New()
