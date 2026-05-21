package command

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	jsg "github.com/alanshaw/dag-json-gen"
	cbg "github.com/whyrusleeping/cbor-gen"
)

const separator = "/"

// Command is a concrete message (a "verb") that MUST be unambiguously
// interpretable by the Subject of a UCAN.
//
// A [Command] is composed of a leading slash which is optionally followed by
// one or more slash-separated Segments of lowercase characters.
//
// The underlying field is unexported so a Command can only be obtained from a
// validating constructor ([New], [Parse], [MustParse] or [Top]). This makes
// invalid Commands unrepresentable: a value of this type is always either the
// undefined zero value or a well-formed command.
//
// Note: this is a struct rather than `type Command string` for two reasons —
// it prevents arbitrary strings being converted into a Command, and cbor-gen
// only recognises MarshalCBOR/UnmarshalCBOR on non-string (struct) types.
//
// [Command]: https://github.com/ucan-wg/spec#command
type Command struct {
	str string
}

// Undef is the zero value of Command, representing an undefined command. Using
// Command{} directly is also acceptable.
var Undef = Command{}

// Defined reports whether the Command holds a value (i.e. is not the undefined
// zero value).
func (c Command) Defined() bool {
	return c.str != ""
}

// New creates a command from the provided segments. Segments are assumed to be
// well-formed; New does not validate them. To validate untrusted input, use
// [Parse].
func New(segments ...string) Command {
	return Top().Join(segments...)
}

// Parse verifies that the provided string contains the required [segment
// structure] and, if valid, returns the resulting Command.
//
// [segment structure]: https://github.com/ucan-wg/spec#segment-structure
func Parse(s string) (Command, error) {
	if !strings.HasPrefix(s, "/") {
		return Undef, ErrRequiresLeadingSlash
	}

	if len(s) > 1 && strings.HasSuffix(s, "/") {
		return Undef, ErrDisallowsTrailingSlash
	}

	if s != strings.ToLower(s) {
		return Undef, ErrRequiresLowercase
	}

	// The leading slash will result in the first element from strings.Split
	// being an empty string which is removed as strings.Join will ignore it.
	return Command{str: s}, nil
}

// MustParse is like [Parse] but panics if s is not a valid Command. It is
// intended for package-level command definitions from constant strings.
func MustParse(s string) Command {
	cmd, err := Parse(s)
	if err != nil {
		panic(fmt.Sprintf("command: MustParse(%q): %v", s, err))
	}
	return cmd
}

// Top is the most powerful capability.
//
// This function returns a Command that is a wildcard and therefore represents
// the most powerful ability. As such, it should be handled with care and used
// sparingly.
//
// [Top]: https://github.com/ucan-wg/spec#-aka-top
func Top() Command {
	return Command{str: separator}
}

// Join appends segments to the end of this command using the required
// segment separator.
func (c Command) Join(segments ...string) Command {
	size := 0
	for _, s := range segments {
		size += len(s)
	}
	if size == 0 {
		return c
	}
	buf := make([]byte, 0, len(c.str)+size+len(segments))
	buf = append(buf, []byte(c.str)...)
	for _, s := range segments {
		if s != "" {
			if len(buf) > 1 {
				buf = append(buf, separator...)
			}
			buf = append(buf, []byte(s)...)
		}
	}
	return Command{str: string(buf)}
}

// Segments returns the ordered segments that comprise the Command as a slice
// of strings.
func (c Command) Segments() []string {
	if c.str == separator {
		return nil
	}
	return strings.Split(c.str, separator)[1:]
}

// Proves returns true if the command is identical or a parent of the given
// other command.
//
// For example, /crypto MAY be used to prove /crypto/sign but MUST NOT prove
// /stack/pop or /cryptocurrency.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#segment-structure
func (c Command) Proves(other Command) bool {
	// fast-path, equivalent to the code below (verified with fuzzing)
	if !strings.HasPrefix(other.str, c.str) {
		return false
	}
	return c.str == separator || len(c.str) == len(other.str) || other.str[len(c.str)] == separator[0]
}

// String returns the composed representation the command. This is also the
// required wire representation (before IPLD encoding occurs).
func (c Command) String() string {
	return c.str
}

func (c Command) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	if err := c.MarshalDagJSON(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Command) UnmarshalJSON(b []byte) error {
	return c.UnmarshalDagJSON(bytes.NewReader(b))
}

func (c Command) MarshalCBOR(w io.Writer) error {
	if c.str == "" {
		_, err := w.Write(cbg.CborNull)
		return err
	}
	cw := cbg.NewCborWriter(w)
	if err := cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len(c.str))); err != nil {
		return err
	}
	_, err := cw.WriteString(c.str)
	return err
}

func (c *Command) UnmarshalCBOR(r io.Reader) error {
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
		*c = parsed
	}
	return nil
}

func (c Command) MarshalDagJSON(w io.Writer) error {
	jw := jsg.NewDagJsonWriter(w)
	if c.str == "" {
		return jw.WriteNull()
	}
	return jw.WriteString(c.str)
}

func (c *Command) UnmarshalDagJSON(r io.Reader) error {
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
	*c = parsed
	return nil
}

var (
	_ fmt.Stringer        = (*Command)(nil)
	_ cbg.CBORMarshaler   = (*Command)(nil)
	_ cbg.CBORUnmarshaler = (*Command)(nil)
)
