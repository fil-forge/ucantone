package multiformat

import (
	"bytes"
	"fmt"

	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
)

func TagWith(code multicodec.Code, bytes []byte) []byte {
	offset := varint.UvarintSize(uint64(code))
	tagged := make([]byte, len(bytes)+offset)
	varint.PutUvarint(tagged, uint64(code))
	copy(tagged[offset:], bytes)
	return tagged
}

func UntagWith(code multicodec.Code, source []byte, offset int) ([]byte, error) {
	b := source
	if offset != 0 {
		b = source[offset:]
	}

	tag, err := varint.ReadUvarint(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	if tag != uint64(code) {
		return nil, fmt.Errorf("expected multiformat with tag %s [0x%02x] instead got %s [0x%02x]", code, uint64(code), multicodec.Code(tag), tag)
	}

	size := varint.UvarintSize(uint64(code))
	return b[size:], nil
}
