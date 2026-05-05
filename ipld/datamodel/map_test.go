package datamodel_test

import (
	"bytes"
	"maps"
	"slices"
	"testing"

	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/stretchr/testify/require"
)

func TestMap(t *testing.T) {
	t.Run("get", func(t *testing.T) {
		bytesValue := []byte{1, 2, 3}
		initial := datamodel.Map{"bytes": bytesValue}

		var buf bytes.Buffer
		err := initial.MarshalCBOR(&buf)
		require.NoError(t, err)

		var decoded datamodel.Map
		err = decoded.UnmarshalCBOR(&buf)
		require.NoError(t, err)

		value, ok := decoded["bytes"]
		require.True(t, ok)
		require.Equal(t, bytesValue, value)
	})

	t.Run("keys", func(t *testing.T) {
		initial := datamodel.Map{"bytes": []byte{1, 2, 3}}

		var buf bytes.Buffer
		err := initial.MarshalCBOR(&buf)
		require.NoError(t, err)

		var decoded datamodel.Map
		err = decoded.UnmarshalCBOR(&buf)
		require.NoError(t, err)
		require.Equal(t, []string{"bytes"}, slices.Collect(maps.Keys(decoded)))
	})

	t.Run("empty", func(t *testing.T) {
		initial := datamodel.Map{}

		var buf bytes.Buffer
		err := initial.MarshalCBOR(&buf)
		require.NoError(t, err)

		var decoded datamodel.Map
		err = decoded.UnmarshalCBOR(&buf)
		require.NoError(t, err)
		require.Len(t, slices.Collect(maps.Keys(decoded)), 0)
	})
}
