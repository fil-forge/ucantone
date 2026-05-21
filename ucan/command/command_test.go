package command_test

import (
	"bytes"
	"testing"

	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/stretchr/testify/require"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		err  error
	}{
		{"root", "/", nil},
		{"single segment", "/foo", nil},
		{"multi segment", "/foo/bar/baz", nil},
		{"missing leading slash", "foo/bar", command.ErrRequiresLeadingSlash},
		{"empty", "", command.ErrRequiresLeadingSlash},
		{"trailing slash", "/foo/", command.ErrDisallowsTrailingSlash},
		{"uppercase", "/Foo", command.ErrRequiresLowercase},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := command.Parse(tc.in)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				require.False(t, cmd.Defined())
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.in, cmd.String())
		})
	}
}

func TestMustParse(t *testing.T) {
	require.Equal(t, "/foo/bar", command.MustParse("/foo/bar").String())
	require.Panics(t, func() { command.MustParse("bad") })
}

func TestUndef(t *testing.T) {
	require.False(t, command.Undef.Defined())
	require.True(t, command.MustParse("/foo").Defined())
	// Comparable: two equal commands are ==.
	require.Equal(t, command.MustParse("/foo"), command.MustParse("/foo"))
}

func TestCBORRoundTrip(t *testing.T) {
	want := command.MustParse("/foo/bar")

	var buf bytes.Buffer
	require.NoError(t, want.MarshalCBOR(&buf))

	var got command.Command
	require.NoError(t, got.UnmarshalCBOR(bytes.NewReader(buf.Bytes())))
	require.Equal(t, want, got)
}

// TestCBORDecodeValidates is the guarantee the struct buys us: a non-conforming
// command on the wire is rejected at decode time rather than producing an
// invalid in-memory Command.
func TestCBORDecodeValidates(t *testing.T) {
	var buf bytes.Buffer
	cw := cbg.NewCborWriter(&buf)
	require.NoError(t, cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len("nofwdslash"))))
	_, err := cw.WriteString("nofwdslash")
	require.NoError(t, err)

	var got command.Command
	require.ErrorIs(t, got.UnmarshalCBOR(bytes.NewReader(buf.Bytes())), command.ErrRequiresLeadingSlash)
}

func TestDagJSONRoundTrip(t *testing.T) {
	want := command.MustParse("/foo/bar")

	var buf bytes.Buffer
	require.NoError(t, want.MarshalDagJSON(&buf))

	var got command.Command
	require.NoError(t, got.UnmarshalDagJSON(bytes.NewReader(buf.Bytes())))
	require.Equal(t, want, got)
}

func TestDagJSONDecodeValidates(t *testing.T) {
	var got command.Command
	require.ErrorIs(t,
		got.UnmarshalDagJSON(bytes.NewReader([]byte(`"nofwdslash"`))),
		command.ErrRequiresLeadingSlash)
}

func TestProves(t *testing.T) {
	crypto := command.MustParse("/crypto")
	require.True(t, crypto.Proves(command.MustParse("/crypto")))
	require.True(t, crypto.Proves(command.MustParse("/crypto/sign")))
	require.True(t, command.Top().Proves(crypto))
	require.False(t, crypto.Proves(command.MustParse("/cryptocurrency")))
	require.False(t, crypto.Proves(command.MustParse("/stack/pop")))
}
