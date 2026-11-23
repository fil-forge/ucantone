package did_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fil-forge/ucantone/did"
)

func TestParse(t *testing.T) {
	t.Run("did:key", func(t *testing.T) {
		str := "did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z"
		d, err := did.Parse(str)
		require.NoError(t, err)
		require.Equal(t, str, d.String())
	})

	t.Run("did:web", func(t *testing.T) {
		str := "did:web:up.storacha.network"
		d, err := did.Parse(str)
		require.NoError(t, err)
		require.Equal(t, str, d.String())
	})

	t.Run("accepts", func(t *testing.T) {
		for _, str := range []string{
			"did:web:example.com%3A3000:user:alice",
			"did:mailto:web.mail:alice",
			"did:mailto:example.com:alice%2Btag",
			"did:plc:ewvi7nxzyoun6zhxrhs64oiz",
			"did:example:123456789abcdefghi",
			"did:example::a",
			"did:ex4mple:A-b_c.d",
		} {
			d, err := did.Parse(str)
			require.NoError(t, err, str)
			require.Equal(t, str, d.String())
		}
	})

	t.Run("rejects", func(t *testing.T) {
		cases := map[string]string{
			"":                              "must start with 'did:'",
			"web:example.com":               "must start with 'did:'",
			"DID:web:example.com":           "must start with 'did:'",
			"did:":                          "method and an identifier",
			"did:web":                       "method and an identifier",
			"did::example.com":              "method is empty",
			"did:Web:example.com":           "lower case letters and digits",
			"did:we-b:example.com":          "lower case letters and digits",
			"did:web:":                      "identifier is empty",
			"did:web:example.com:":          "must not end with ':'",
			"did:web:example.com/user":      "must be percent-encoded",
			"did:web:example.com?x=1":       "must be percent-encoded",
			"did:web:example.com#key-0":     "must be percent-encoded",
			"did:web:example.com:~alice":    "must be percent-encoded",
			"did:web:example .com":          "must be percent-encoded",
			"did:mailto:example.com:a@b":    "must be percent-encoded",
			"did:web:ex\u00e4mple.com":      "must be percent-encoded",
			"did:web:example.com%3":         "malformed percent-escape",
			"did:web:example.com%zz":        "malformed percent-escape",
			"did:web:example.com%":          "malformed percent-escape",
			"did:key:z6Mkod5Jr3yd5SC7UDu0O": "",
			"did:key:abc":                   "",
		}
		for str, want := range cases {
			_, err := did.Parse(str)
			require.Error(t, err, str)
			if want != "" {
				require.ErrorContains(t, err, want, str)
			}
		}
	})
}

func TestNew(t *testing.T) {
	t.Run("builds a DID from a method and an identifier", func(t *testing.T) {
		d, err := did.New("web", "example.com%3A3000:user:alice")
		require.NoError(t, err)
		require.Equal(t, "did:web:example.com%3A3000:user:alice", d.String())
		require.Equal(t, "web", d.Method())
		require.Equal(t, "example.com%3A3000:user:alice", d.Identifier())
	})

	t.Run("rejects what Parse rejects", func(t *testing.T) {
		cases := []struct{ method, identifier, want string }{
			{"", "example.com", "method is empty"},
			{"Web", "example.com", "lower case letters and digits"},
			{"web", "", "identifier is empty"},
			{"web", "example.com:", "must not end with ':'"},
			{"mailto", "example.com:a~b", "must be percent-encoded"},
			{"web", "example.com%3", "malformed percent-escape"},
			{"key", "abc", ""},
		}
		for _, tt := range cases {
			_, err := did.New(tt.method, tt.identifier)
			require.Error(t, err, "%s:%s", tt.method, tt.identifier)
			if tt.want != "" {
				require.ErrorContains(t, err, tt.want)
			}
		}
	})
}

func TestMethod(t *testing.T) {
	cases := map[string]string{
		"did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z": "key",
		"did:web:up.storacha.network":                              "web",
		"did:mailto:web.mail:alice":                                "mailto",
	}
	for input, want := range cases {
		d, err := did.Parse(input)
		require.NoError(t, err)
		require.Equal(t, want, d.Method(), input)
	}
	require.Equal(t, "", did.Undef.Method())
}

func TestIdentifier(t *testing.T) {
	cases := map[string]string{
		"did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z": "z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z",
		"did:web:up.whatever.network":                              "up.whatever.network",
		"did:mailto:web.mail:alice":                                "web.mail:alice",
	}
	for input, want := range cases {
		d, err := did.Parse(input)
		require.NoError(t, err)
		require.Equal(t, want, d.Identifier(), input)
	}
	require.Equal(t, "", did.Undef.Identifier())
}

func TestEquivalence(t *testing.T) {
	d0, err := did.Parse("did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z")
	require.NoError(t, err)

	d1, err := did.Parse("did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z")
	require.NoError(t, err)

	if d0 != d1 {
		require.Fail(t, "DIDs were not equal")
	}

	require.Equal(t, d0, d1)
}

func TestMapKey(t *testing.T) {
	d0, err := did.Parse("did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z")
	require.NoError(t, err)

	d1, err := did.Parse("did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z")
	require.NoError(t, err)

	m := map[did.DID]string{}
	m[d0] = "test"
	require.Equal(t, "test", m[d1])
}

func TestRoundtripJSON(t *testing.T) {
	id, err := did.Parse("did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z")
	require.NoError(t, err)

	type Object struct {
		ID                did.DID  `json:"id"`
		UndefID           did.DID  `json:"undef_id"`
		OptionalPresentID *did.DID `json:"optional_present_id"`
		OptionalAbsentID  *did.DID `json:"optional_absent_id"`
	}

	var undef did.DID
	obj := Object{
		ID:                id,
		UndefID:           undef,
		OptionalPresentID: &id,
		OptionalAbsentID:  nil,
	}

	data, err := json.Marshal(obj)
	require.NoError(t, err)

	t.Log(string(data))

	var out Object
	err = json.Unmarshal(data, &out)
	require.NoError(t, err)

	require.Equal(t, obj.ID, out.ID)
	require.Equal(t, obj.UndefID, out.UndefID)
	require.Equal(t, obj.OptionalPresentID.String(), out.OptionalPresentID.String())
	require.Nil(t, out.OptionalAbsentID)
}
