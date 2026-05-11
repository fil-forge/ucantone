package did_test

import (
	"encoding/json"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Run("did:key", func(t *testing.T) {
		str := "did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z"
		d, err := did.Parse(str)
		require.NoError(t, err)
		require.Equal(t, str, d.String())
		require.Equal(t, "key", d.Method())
		require.Equal(t, "z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z", d.ID())
	})

	t.Run("did:web", func(t *testing.T) {
		str := "did:web:up.storacha.network"
		d, err := did.Parse(str)
		require.NoError(t, err)
		require.Equal(t, str, d.String())
		require.Equal(t, "web", d.Method())
		require.Equal(t, "up.storacha.network", d.ID())
	})

	t.Run("did:example", func(t *testing.T) {
		str := "did:example:abc123"
		d, err := did.Parse(str)
		require.NoError(t, err)
		require.Equal(t, str, d.String())
		require.Equal(t, "example", d.Method())
		require.Equal(t, "abc123", d.ID())
	})
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
