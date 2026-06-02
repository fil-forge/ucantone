package varsig

import (
	"fmt"

	"github.com/fil-forge/ucantone/varsig/algorithm"
	"github.com/fil-forge/ucantone/varsig/algorithm/ecdsa"
	"github.com/fil-forge/ucantone/varsig/algorithm/eddsa"
)

func init() {
	// Register spec-defined signature algorithms.
	RegisterAlgorithmScheme(algorithm.AlgorithmDef{
		Code:    eddsa.Code,
		Name:    "EdDSA",
		Decoder: eddsa.Decode,
	})
	RegisterAlgorithmScheme(algorithm.AlgorithmDef{
		Code:    ecdsa.Code,
		Name:    "ECDSA",
		Decoder: ecdsa.Decode,
	})

	// BLS12_381 and RSASSA-PKCS #1 are not yet implemented.
}

// AlgorithmScheme represents the choice of an algorithm scheme, the first field
// in the signature algorithm segment of a Varsig. This is the top-level
// discriminant, and determines what other fields should follow. This is NOT a
// multicodec code! These codes are defined directly by Varsig, and are not in
// the multicodec table.
//
// https://github.com/ChainAgnostic/varsig#signature-algorithm
type AlgorithmScheme uint64

type AlgorithmSchemeDef = algorithm.AlgorithmDef

var signatureAlgorithmDefs = map[AlgorithmScheme]AlgorithmSchemeDef{}

// Algorithm represents the choice of an entire signature algorithm as part of a
// Varsig. It's a code and any additional fields needed to configure it.
type Algorithm = algorithm.Algorithm

// RegisterAlgorithmScheme registers a signature algorithm definition, which includes
// the name and decoder for the algorithm. Technically, Varsig's list of
// signature algorithms is closed. However, unofficially, codes in Multicodec's
// private use area (0x300000–0x3FFFFF) should be safe to use for
// application-specific purposes (even though these are not actually Multicodec
// codes).
func RegisterAlgorithmScheme(def AlgorithmSchemeDef) {
	signatureAlgorithmDefs[AlgorithmScheme(def.Code)] = def
}

func (pe AlgorithmScheme) String() string {
	def, ok := signatureAlgorithmDefs[pe]
	if !ok {
		return fmt.Sprintf("<unknown: 0x%02x>", uint64(pe))
	}
	return def.Name
}

func (pe AlgorithmScheme) Decode(input []byte) (algorithm.Algorithm, int, error) {
	def, ok := signatureAlgorithmDefs[pe]
	if !ok {
		return nil, 0, fmt.Errorf("unknown signature algorithm scheme: 0x%02x", uint64(pe))
	}
	alg, n, err := def.Decoder(input)
	if err != nil {
		return nil, n, fmt.Errorf("decoding signature algorithm: %w", err)
	}
	return alg, n, nil
}
