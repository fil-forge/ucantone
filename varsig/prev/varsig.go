package prev

import (
	"fmt"
	"strconv"
	"strings"

	varint "github.com/multiformats/go-varint"
)

const Prefix = 0x34
const Version = 0x01

type Codec[T any] interface {
	Code() uint64
	Encode() ([]byte, error)
	Decode([]byte) (T, int, error)
}

type SignatureAlgorithm interface {
	// Discriminant for the signature segments.
	Code() uint64
	// Signature segments including the signature algorithm code.
	Segments() []uint64
}

type SignatureAlgorithmCodec[T SignatureAlgorithm] interface {
	SignatureAlgorithm
	Codec[T]
}

// code -> segments -> codec
var signatureAlgorithmCodecs = map[uint64]map[string]SignatureAlgorithmCodec[SignatureAlgorithm]{}

func signatureAlgorithmSegmentKey(segments []uint64) string {
	k := make([]string, 0, len(segments))
	for _, s := range segments {
		k = append(k, strconv.FormatUint(s, 16))
	}
	return strings.Join(k, "-")
}

type signatureAlgorithmCodecAdapter[T SignatureAlgorithm] struct {
	codec SignatureAlgorithmCodec[T]
}

func (a signatureAlgorithmCodecAdapter[T]) Code() uint64 {
	return a.codec.Code()
}

func (a signatureAlgorithmCodecAdapter[T]) Segments() []uint64 {
	return a.codec.Segments()
}

func (a signatureAlgorithmCodecAdapter[T]) Encode() ([]byte, error) {
	return a.codec.Encode()
}

func (a signatureAlgorithmCodecAdapter[T]) Decode(input []byte) (SignatureAlgorithm, int, error) {
	algo, n, err := a.codec.Decode(input)
	if err != nil {
		return nil, 0, err
	}
	return SignatureAlgorithm(algo), n, nil
}

func RegisterSignatureAlgorithm[T SignatureAlgorithm](codec SignatureAlgorithmCodec[T]) {
	codecs, ok := signatureAlgorithmCodecs[codec.Code()]
	if !ok {
		codecs = map[string]SignatureAlgorithmCodec[SignatureAlgorithm]{}
		signatureAlgorithmCodecs[codec.Code()] = codecs
	}
	codecs[signatureAlgorithmSegmentKey(codec.Segments())] = signatureAlgorithmCodecAdapter[T]{codec}
}

// GetSignatureAlgorithmCodec returns a registered codec for the given signature algorithm. The boolean will be false if no codec is registered for the algorithm.
func GetSignatureAlgorithmCodec(algo SignatureAlgorithm) (SignatureAlgorithmCodec[SignatureAlgorithm], bool) {
	codecs, ok := signatureAlgorithmCodecs[algo.Code()]
	if !ok {
		return nil, false
	}
	c, ok := codecs[signatureAlgorithmSegmentKey(algo.Segments())]
	return c, ok
}

type PayloadEncoding interface {
	// Discriminant for the payload encoding segments.
	Code() uint64
}

type PayloadEncodingCodec[T PayloadEncoding] Codec[T]

var payloadEncodingCodecs = map[uint64]PayloadEncodingCodec[PayloadEncoding]{}

type payloadEncodingCodecAdapter[T PayloadEncoding] struct {
	codec PayloadEncodingCodec[T]
}

func (a payloadEncodingCodecAdapter[T]) Code() uint64 {
	return a.codec.Code()
}

func (a payloadEncodingCodecAdapter[T]) Encode() ([]byte, error) {
	return a.codec.Encode()
}

func (a payloadEncodingCodecAdapter[T]) Decode(input []byte) (PayloadEncoding, int, error) {
	algo, n, err := a.codec.Decode(input)
	if err != nil {
		return nil, 0, err
	}
	return PayloadEncoding(algo), n, nil
}

func RegisterPayloadEncoding[T PayloadEncoding](codec PayloadEncodingCodec[T]) {
	payloadEncodingCodecs[codec.Code()] = payloadEncodingCodecAdapter[T]{codec}
}

// GetPayloadEncodingCodec returns a registered codec for the given payload
// encoding. The boolean will be false if no codec is registered for the encoding.
func GetPayloadEncodingCodec(enc PayloadEncoding) (PayloadEncodingCodec[PayloadEncoding], bool) {
	c, ok := payloadEncodingCodecs[enc.Code()]
	return c, ok
}

type VarsigHeader interface {
	// A Varsig v1 MUST use the 0x01 version tag.
	Version() uint64
	SignatureAlgorithm() SignatureAlgorithm
	PayloadEncoding() PayloadEncoding
}

type Header struct {
	signatureAlgorithm SignatureAlgorithm
	payloadEncoding    PayloadEncoding
}

func NewHeader(sigAlgo SignatureAlgorithm, payloadEnc PayloadEncoding) Header {
	return Header{sigAlgo, payloadEnc}
}

func (h Header) Version() uint64 {
	return Version
}

func (h Header) SignatureAlgorithm() SignatureAlgorithm {
	return h.signatureAlgorithm
}

func (h Header) PayloadEncoding() PayloadEncoding {
	return h.payloadEncoding
}

var _ VarsigHeader = (*Header)(nil)

func Encode(header VarsigHeader) ([]byte, error) {
	size := varint.UvarintSize(Prefix)
	size += varint.UvarintSize(Version)

	sigAlgoCodec, ok := GetSignatureAlgorithmCodec(header.SignatureAlgorithm())
	if !ok {
		return nil, fmt.Errorf("missing codec for signature algorithm: %d", header.SignatureAlgorithm().Code())
	}
	sigAlgoBytes, err := sigAlgoCodec.Encode()
	if err != nil {
		return nil, err
	}
	size += len(sigAlgoBytes)

	payloadEncCodec, ok := GetPayloadEncodingCodec(header.PayloadEncoding())
	if !ok {
		return nil, fmt.Errorf("missing codec for payload encoding: %d", header.PayloadEncoding().Code())
	}
	payloadEncBytes, err := payloadEncCodec.Encode()
	if err != nil {
		return nil, err
	}
	size += len(payloadEncBytes)

	out := make([]byte, size)
	offset := varint.PutUvarint(out, Prefix)
	offset += varint.PutUvarint(out[offset:], Version)
	offset += copy(out[offset:], sigAlgoBytes)
	offset += copy(out[offset:], payloadEncBytes)
	return out, nil
}

func Decode(input []byte) (Header, error) {
	offset := 0
	prefix, n, err := varint.FromUvarint(input)
	if err != nil {
		return Header{}, fmt.Errorf("reading prefix: %w", err)
	}
	if prefix != Prefix {
		return Header{}, fmt.Errorf("invalid varsig prefix: 0x%02x, expected: 0x%02x", prefix, Prefix)
	}
	offset += n

	version, n, err := varint.FromUvarint(input[offset:])
	if err != nil {
		return Header{}, fmt.Errorf("reading version: %w", err)
	}
	if version != Version {
		return Header{}, fmt.Errorf("invalid varsig version: 0x%02x, expected: 0x%02x", version, Version)
	}
	offset += n

	sigAlgoCode, _, err := varint.FromUvarint(input[offset:])
	if err != nil {
		return Header{}, fmt.Errorf("reading signature algorithm code: %w", err)
	}

	codecs, ok := signatureAlgorithmCodecs[sigAlgoCode]
	if !ok {
		return Header{}, fmt.Errorf("unsupported signature algorithm codec: 0x%02x", sigAlgoCode)
	}
	var sigAlgo SignatureAlgorithm
	for _, codec := range codecs {
		sa, n, err := codec.Decode(input[offset:])
		if err != nil {
			continue
		}
		sigAlgo = sa
		offset += n
		break
	}
	if sigAlgo == nil {
		return Header{}, fmt.Errorf("unsupported signature algorithm code: 0x%02x", sigAlgoCode)
	}

	payloadEncCode, _, err := varint.FromUvarint(input[offset:])
	if err != nil {
		return Header{}, fmt.Errorf("reading payload encoding code: %w", err)
	}
	payloadEncCodec, ok := payloadEncodingCodecs[payloadEncCode]
	if !ok {
		return Header{}, fmt.Errorf("unsupported payload encoding codec: 0x%02x", payloadEncCode)
	}
	payloadEnc, _, err := payloadEncCodec.Decode(input[offset:])
	if err != nil {
		return Header{}, fmt.Errorf("decoding payload encoding: %w", err)
	}

	return Header{sigAlgo, payloadEnc}, nil
}
