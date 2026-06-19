package varsig

import "fmt"

// PayloadEncoding represents the choice of a payload encoding as part of a
// Varsig, describing the encoding used for the payload that is signed. This is
// NOT a multicodec code! These codes are defined directly by Varsig, and are
// not in the multicodec table (though DagCbor and DagJson happen to match).
//
// https://github.com/ChainAgnostic/varsig#payload-encoding
type PayloadEncoding uint64

const (
	ByteIdentical = PayloadEncoding(0x5F)
	DagCbor       = PayloadEncoding(0x71)
	DagJson       = PayloadEncoding(0x0129)
	EIP191        = PayloadEncoding(0xE191)
)

func (pe PayloadEncoding) String() string {
	switch pe {
	case ByteIdentical:
		return "byte-identical"
	case DagCbor:
		return "dag-cbor"
	case DagJson:
		return "dag-json"
	case EIP191:
		return "eip-191"
	default:
		return fmt.Sprintf("<unknown: 0x%02x>", uint64(pe))
	}
}

// Unknown returns true if the payload encoding is not recognized.
func (pe PayloadEncoding) Unknown() bool {
	switch pe {
	case ByteIdentical, DagCbor, DagJson, EIP191:
		return false
	default:
		return true
	}
}
