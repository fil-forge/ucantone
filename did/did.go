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

// TODO: This should really go in `did/key`, but we use it in `did.Parse` to
// validate `did:key` DIDs during parsing. We could drop that, but it's a nice
// check to have.
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

func New(method, identifier string) DID {
	return DID{fmt.Sprintf("%s%s:%s", Prefix, method, identifier)}
}

// Parse parses a DID string, checking it against the DID syntax:
//
//	did:<method>:<identifier>
//
// The method is lower case letters and digits. The identifier is letters,
// digits, ".", "-", "_" and percent-escapes, in segments separated by colons,
// and does not end with a colon. Anything else, such as a path, query or
// fragment, makes the string a DID URL and is refused.
//
// A did:key is also checked to be Base58BTC encoded.
//
// https://www.w3.org/TR/did-core/#did-syntax
func Parse(str string) (DID, error) {
	rest, ok := strings.CutPrefix(str, Prefix)
	if !ok {
		return DID{}, fmt.Errorf("must start with 'did:'")
	}
	method, id, ok := strings.Cut(rest, ":")
	if !ok {
		return DID{}, fmt.Errorf("must have a method and an identifier, as in 'did:method:identifier'")
	}
	if method == "" {
		return DID{}, fmt.Errorf("method is empty")
	}
	for i := 0; i < len(method); i++ {
		if c := method[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9') {
			return DID{}, fmt.Errorf("method %q must be lower case letters and digits", method)
		}
	}
	if id == "" {
		return DID{}, fmt.Errorf("identifier is empty")
	}
	if strings.HasSuffix(id, ":") {
		return DID{}, fmt.Errorf("identifier must not end with ':'")
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case isIDChar(c) || c == ':':
		case c == '%':
			if i+2 >= len(id) || !isHex(id[i+1]) || !isHex(id[i+2]) {
				return DID{}, fmt.Errorf("identifier has a malformed percent-escape at %q", id[i:min(i+3, len(id))])
			}
			i += 2
		default:
			return DID{}, fmt.Errorf("identifier has the character %q, which must be percent-encoded", c)
		}
	}

	// Convenience validation for `did:key` DIDs.
	if method == "key" {
		code, _, err := mbase.Decode(id)
		if err != nil {
			return DID{}, err
		}
		if code != mbase.Base58BTC {
			return DID{}, fmt.Errorf("not Base58BTC encoded")
		}
	}

	return DID{str}, nil
}

// isIDChar reports whether c may appear unescaped in a DID identifier.
func isIDChar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '-' || c == '_'
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func MustParse(str string) DID {
	d, err := Parse(str)
	if err != nil {
		panic(fmt.Sprintf("invalid DID: %s", str))
	}
	return d
}
