package varsig

import (
	"fmt"

	"github.com/fil-forge/ucantone/varsig/algorithm"
	"github.com/multiformats/go-varint"
)

const Prefix = 0x34
const Version = 0x01

// Varsig represents a Varsig v1
// https://github.com/ChainAgnostic/varsig
type Varsig struct {
	sigAlg     algorithm.Algorithm
	payloadEnc PayloadEncoding
}

func New(sigAlg algorithm.Algorithm, payloadEnc PayloadEncoding) Varsig {
	return Varsig{sigAlg: sigAlg, payloadEnc: payloadEnc}
}

func (v Varsig) Version() uint64 {
	return Version
}

func (v Varsig) SignatureAlgorithm() algorithm.Algorithm {
	return v.sigAlg
}

func (v Varsig) PayloadEncoding() PayloadEncoding {
	return v.payloadEnc
}

func (v Varsig) Encode() ([]byte, error) {
	sigAlgBytes, err := v.sigAlg.Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding signature algorithm: %w", err)
	}

	size := varint.UvarintSize(Prefix)
	size += varint.UvarintSize(Version)
	size += len(sigAlgBytes)
	size += varint.UvarintSize(uint64(v.PayloadEncoding()))

	out := make([]byte, size)
	offset := varint.PutUvarint(out, Prefix)
	offset += varint.PutUvarint(out[offset:], Version)
	offset += copy(out[offset:], sigAlgBytes)
	offset += varint.PutUvarint(out[offset:], uint64(v.PayloadEncoding()))
	return out, nil
}

func Decode(input []byte) (Varsig, int, error) {
	offset := 0
	prefix, n, err := varint.FromUvarint(input)
	if err != nil {
		return Varsig{}, 0, fmt.Errorf("reading prefix: %w", err)
	}
	if prefix != Prefix {
		return Varsig{}, 0, fmt.Errorf("invalid varsig prefix: 0x%02x, expected: 0x%02x", prefix, Prefix)
	}
	offset += n

	version, n, err := varint.FromUvarint(input[offset:])
	if err != nil {
		return Varsig{}, 0, fmt.Errorf("reading version: %w", err)
	}
	if version != Version {
		return Varsig{}, 0, fmt.Errorf("invalid varsig version: 0x%02x, expected: 0x%02x", version, Version)
	}
	offset += n

	sigAlgoCode, _, err := varint.FromUvarint(input[offset:])
	if err != nil {
		return Varsig{}, 0, fmt.Errorf("reading signature algorithm code: %w", err)
	}

	sigAlgScheme := AlgorithmScheme(sigAlgoCode)
	sigAlg, n, err := sigAlgScheme.Decode(input[offset:])
	if err != nil {
		return Varsig{}, 0, fmt.Errorf("decoding signature algorithm: %w", err)
	}
	offset += n

	payloadEncCode, n, err := varint.FromUvarint(input[offset:])
	if err != nil {
		return Varsig{}, 0, fmt.Errorf("reading payload encoding code: %w", err)
	}
	payloadEnc := PayloadEncoding(payloadEncCode)
	if payloadEnc.Unknown() {
		return Varsig{}, 0, fmt.Errorf("unknown payload encoding codec: 0x%02x", payloadEncCode)
	}
	offset += n

	return Varsig{sigAlg: sigAlg, payloadEnc: payloadEnc}, offset, nil
}
