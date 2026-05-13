package did

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	jsg "github.com/alanshaw/dag-json-gen"
	mbase "github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
	cbg "github.com/whyrusleeping/cbor-gen"
)

const Prefix = "did:"
const KeyPrefix = Prefix + "key:"

const DIDCore = 0x0d1d
const Ed25519 = 0xed
const RSA = 0x1205
const Secp256k1 = 0xe7

var MethodOffset = varint.UvarintSize(uint64(DIDCore))

// DID is a decentralized identity, it has the format:
//
//	"did:%s:%s"
//
// The underlying type is string, so DIDs are safe to compare with == and to use
// as keys in maps.
//
// Note: this is not `type DID string` because cbor-gen does not recognise
// MarshalCBOR or UnmarshalCBOR when type is not struct.
type DID struct {
	str string
}

// Undef can be used to represent a nil or undefined DID, using DID{}
// directly is also acceptable.
var Undef = DID{}

func (d DID) Defined() bool {
	return d.str != ""
}

// String formats the decentralized identity document (DID) as a string.
func (d DID) String() string {
	return d.str
}

// Method returns the DID method name (e.g. "key", "web") parsed from the
// scheme. Returns "" for an undefined DID.
func (d DID) Method() string {
	rest, ok := strings.CutPrefix(d.str, Prefix)
	if !ok {
		return ""
	}
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		return rest[:i]
	}
	return ""
}

// Identifier returns the method-specific identifier — everything after
// "did:<method>:". Per the DID spec, this segment may itself contain colons
// (e.g. "did:mailto:web.mail:alice" yields "web.mail:alice"). Returns "" for
// an undefined DID.
func (d DID) Identifier() string {
	rest, ok := strings.CutPrefix(d.str, Prefix)
	if !ok {
		return ""
	}
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		return rest[i+1:]
	}
	return ""
}

func (d DID) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	err := d.MarshalDagJSON(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *DID) UnmarshalJSON(b []byte) error {
	return d.UnmarshalDagJSON(bytes.NewReader(b))
}

func (d DID) MarshalCBOR(w io.Writer) error {
	if d.str == "" {
		_, err := w.Write(cbg.CborNull)
		return err
	}
	cw := cbg.NewCborWriter(w)
	if err := cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len(d.str))); err != nil {
		return err
	}
	_, err := cw.WriteString(d.str)
	return err
}

func (d *DID) UnmarshalCBOR(r io.Reader) error {
	cr := cbg.NewCborReader(r)
	b, err := cr.ReadByte()
	if err != nil {
		return err
	}
	if b != cbg.CborNull[0] {
		if err := cr.UnreadByte(); err != nil {
			return err
		}
		str, err := cbg.ReadStringWithMax(cr, 2048)
		if err != nil {
			return err
		}
		parsed, err := Parse(str)
		if err != nil {
			return err
		}
		*d = parsed
	}
	return nil
}

func (d DID) MarshalDagJSON(w io.Writer) error {
	jw := jsg.NewDagJsonWriter(w)
	if d.str == "" {
		return jw.WriteNull()
	}
	return jw.WriteString(d.str)
}

func (d *DID) UnmarshalDagJSON(r io.Reader) error {
	jr := jsg.NewDagJsonReader(r)
	str, err := jr.ReadStringOrNull(jsg.MaxLength)
	if err != nil {
		return err
	}
	if str == nil {
		return nil
	}
	parsed, err := Parse(*str)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

func Parse(str string) (DID, error) {
	if !strings.HasPrefix(str, Prefix) {
		return DID{}, fmt.Errorf("must start with 'did:'")
	}
	if strings.HasPrefix(str, KeyPrefix) {
		code, _, err := mbase.Decode(str[len(KeyPrefix):])
		if err != nil {
			return DID{}, err
		}
		if code != mbase.Base58BTC {
			return DID{}, fmt.Errorf("not Base58BTC encoded")
		}
	}
	return DID{str}, nil
}
