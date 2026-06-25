package did_test

import (
	"encoding/json"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

func TestContext(t *testing.T) {
	t.Run("to JSON", func(t *testing.T) {
		t.Run("with no additional contexts, produces the DID Core context", func(t *testing.T) {
			ctx := did.Context{}
			b, err := json.Marshal(ctx)
			require.NoError(t, err)
			require.JSONEq(t, `"https://www.w3.org/ns/did/v1.1"`, string(b))
		})

		t.Run("with additional contexts, puts the DID Core context first", func(t *testing.T) {
			ctx := did.Context{
				"https://example.com/context1",
				"https://example.com/context2",
			}
			b, err := json.Marshal(ctx)
			require.NoError(t, err)
			require.JSONEq(t, `[
			"https://www.w3.org/ns/did/v1.1",
			"https://example.com/context1",
			"https://example.com/context2"
		]`, string(b))
		})
	})

	t.Run("from JSON", func(t *testing.T) {
		t.Run("with a single string of the DID Core context, produces an empty Context", func(t *testing.T) {
			var ctx did.Context
			err := json.Unmarshal([]byte(`"https://www.w3.org/ns/did/v1.1"`), &ctx)
			require.NoError(t, err)
			require.Equal(t, did.Context{}, ctx)
		})

		t.Run("with a single string of the wrong context, fails", func(t *testing.T) {
			var ctx did.Context
			err := json.Unmarshal([]byte(`"https://example.com/wrong-context"`), &ctx)
			require.ErrorContains(t, err, `@context must list "https://www.w3.org/ns/did/v1.1" or "https://www.w3.org/ns/did/v1" first`)
		})

		t.Run("accepts the DID Core v1.0 context for interoperability", func(t *testing.T) {
			var ctx did.Context
			err := json.Unmarshal([]byte(`["https://www.w3.org/ns/did/v1", "https://example.com/context1"]`), &ctx)
			require.NoError(t, err)
			require.Equal(t, did.Context{"https://example.com/context1"}, ctx)
		})

		t.Run("with multiple contexts, puts them in the Context", func(t *testing.T) {
			var ctx did.Context
			err := json.Unmarshal([]byte(`["https://www.w3.org/ns/did/v1.1", "https://example.com/context1"]`), &ctx)
			require.NoError(t, err)
			require.Equal(t, did.Context{"https://example.com/context1"}, ctx)
		})

		t.Run("with multiple contexts missing the DID Core context, fails", func(t *testing.T) {
			var ctx did.Context
			err := json.Unmarshal([]byte(`["https://example.com/context1", "https://example.com/context2"]`), &ctx)
			require.ErrorContains(t, err, `@context must list "https://www.w3.org/ns/did/v1.1" or "https://www.w3.org/ns/did/v1" first`)
		})

		t.Run("with no contexts, fails", func(t *testing.T) {
			var ctx did.Context
			err := json.Unmarshal([]byte(`[]`), &ctx)
			require.ErrorContains(t, err, `@context must list "https://www.w3.org/ns/did/v1.1" or "https://www.w3.org/ns/did/v1" first`)
		})
	})
}
