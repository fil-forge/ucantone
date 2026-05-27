package document_test

import (
	"encoding/json"
	"testing"

	"github.com/fil-forge/ucantone/did/document"
	"github.com/stretchr/testify/require"
)

func TestOneOrMany(t *testing.T) {
	t.Run("to JSON", func(t *testing.T) {
		t.Run("with one string, produces a string", func(t *testing.T) {
			oom := document.OneOrMany[string]{"one value"}
			b, err := json.Marshal(oom)
			require.NoError(t, err)
			require.JSONEq(t, `"one value"`, string(b))
		})

		t.Run("with multiple strings, produces an array", func(t *testing.T) {
			oom := document.OneOrMany[string]{"one value", "another value"}
			b, err := json.Marshal(oom)
			require.NoError(t, err)
			require.JSONEq(t, `["one value", "another value"]`, string(b))
		})

		t.Run("with one map, produces a map", func(t *testing.T) {
			oom := document.OneOrMany[map[string]string]{{"key": "value"}}
			b, err := json.Marshal(oom)
			require.NoError(t, err)
			require.JSONEq(t, `{"key": "value"}`, string(b))
		})

		t.Run("with multiple maps, produces an array of maps", func(t *testing.T) {
			oom := document.OneOrMany[map[string]string]{{"key": "value"}, {"another": "map"}}
			b, err := json.Marshal(oom)
			require.NoError(t, err)
			require.JSONEq(t, `[{"key": "value"}, {"another": "map"}]`, string(b))
		})

		t.Run("with no values, produces an empty array", func(t *testing.T) {
			oom := document.OneOrMany[string]{}
			b, err := json.Marshal(oom)
			require.NoError(t, err)
			require.JSONEq(t, `[]`, string(b))
		})
	})

	t.Run("from JSON", func(t *testing.T) {
		t.Run("with a single string, produces an OneOrMany with one element", func(t *testing.T) {
			var oom document.OneOrMany[string]
			err := json.Unmarshal([]byte(`"one value"`), &oom)
			require.NoError(t, err)
			require.Equal(t, document.OneOrMany[string]{"one value"}, oom)
		})

		t.Run("with multiple strings, produces an OneOrMany with multiple elements", func(t *testing.T) {
			var oom document.OneOrMany[string]
			err := json.Unmarshal([]byte(`["one value", "another value"]`), &oom)
			require.NoError(t, err)
			require.Equal(t, document.OneOrMany[string]{"one value", "another value"}, oom)
		})

		t.Run("with a single map, produces an OneOrMany with one element", func(t *testing.T) {
			var oom document.OneOrMany[map[string]string]
			err := json.Unmarshal([]byte(`{"key": "value"}`), &oom)
			require.NoError(t, err)
			require.Equal(t, document.OneOrMany[map[string]string]{{"key": "value"}}, oom)
		})

		t.Run("with multiple maps, produces an OneOrMany with multiple elements", func(t *testing.T) {
			var oom document.OneOrMany[map[string]string]
			err := json.Unmarshal([]byte(`[{"key": "value"}, {"another": "map"}]`), &oom)
			require.NoError(t, err)
			require.Equal(t, document.OneOrMany[map[string]string]{{"key": "value"}, {"another": "map"}}, oom)
		})

		t.Run("with an empty array, produces an empty OneOrMany", func(t *testing.T) {
			var oom document.OneOrMany[string]
			err := json.Unmarshal([]byte(`[]`), &oom)
			require.NoError(t, err)
			require.Equal(t, document.OneOrMany[string]{}, oom)
		})
	})
}
