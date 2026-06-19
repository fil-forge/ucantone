package did_test

import (
	"encoding/json"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

func TestURL(t *testing.T) {
	t.Run("to JSON", func(t *testing.T) {
		url, err := did.ParseURL("https://example.com")
		require.NoError(t, err)
		b, err := json.Marshal(url)
		require.NoError(t, err)
		require.JSONEq(t, `"https://example.com"`, string(b))
	})

	t.Run("from JSON", func(t *testing.T) {
		t.Run("legal URL", func(t *testing.T) {
			var url did.URL
			err := json.Unmarshal([]byte(`"https://example.com"`), &url)
			require.NoError(t, err)
			expectedURL, err := did.ParseURL("https://example.com")
			require.NoError(t, err)
			require.Equal(t, expectedURL, url)
		})

		t.Run("illegal URL", func(t *testing.T) {
			var url did.URL
			err := json.Unmarshal([]byte(`":not a url:"`), &url)
			require.Error(t, err)
		})
	})
}
