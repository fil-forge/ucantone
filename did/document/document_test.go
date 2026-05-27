package document_test

import (
	"encoding/json"
	"testing"

	"github.com/fil-forge/ucantone/did/document"
	"github.com/stretchr/testify/require"
)

func TestDocument_UnmarshalJSON(t *testing.T) {
	t.Run("URL references only", func(t *testing.T) {
		data := `{
			"@context": "https://www.w3.org/ns/did/v1.1",
			"id": "did:example:123",
			"verificationMethod": [{
				"id": "did:example:123#key-1",
				"type": "Multikey",
				"controller": "did:example:123",
				"publicKeyMultibase": "zABC"
			}],
			"authentication": ["did:example:123#key-1"]
		}`
		var doc document.Document
		err := json.Unmarshal([]byte(data), &doc)
		require.NoError(t, err)
		require.Len(t, doc.VerificationMethods, 1)
		require.Equal(t, 1, doc.Authentication.Len())
		require.Equal(t, "did:example:123#key-1", doc.Authentication.Get(0).String())
	})

	t.Run("embedded method in authentication", func(t *testing.T) {
		data := `{
			"@context": "https://www.w3.org/ns/did/v1.1",
			"id": "did:example:123",
			"authentication": [{
				"id": "did:example:123#key-1",
				"type": "Multikey",
				"controller": "did:example:123",
				"publicKeyMultibase": "zABC"
			}]
		}`
		var doc document.Document
		err := json.Unmarshal([]byte(data), &doc)
		require.NoError(t, err)
		require.Len(t, doc.VerificationMethods.All(), 1)
		require.Equal(t, "did:example:123#key-1", doc.VerificationMethods.All()[0].ID.String())
		require.Equal(t, 1, doc.Authentication.Len())
		require.Equal(t, "did:example:123#key-1", doc.Authentication.Get(0).String())
	})

	t.Run("mixed URL and embedded in same relationship", func(t *testing.T) {
		data := `{
			"@context": "https://www.w3.org/ns/did/v1.1",
			"id": "did:example:123",
			"verificationMethod": [{
				"id": "did:example:123#key-1",
				"type": "Multikey",
				"controller": "did:example:123",
				"publicKeyMultibase": "zABC"
			}],
			"authentication": [
				"did:example:123#key-1",
				{
					"id": "did:example:123#key-2",
					"type": "Multikey",
					"controller": "did:example:123",
					"publicKeyMultibase": "zDEF"
				}
			]
		}`
		var doc document.Document
		err := json.Unmarshal([]byte(data), &doc)
		require.NoError(t, err)
		require.Len(t, doc.VerificationMethods.All(), 2)
		require.Equal(t, 2, doc.Authentication.Len())
		require.Equal(t, "did:example:123#key-1", doc.Authentication.Get(0).String())
		require.Equal(t, "did:example:123#key-2", doc.Authentication.Get(1).String())
	})

	t.Run("same embedded method in multiple relationships", func(t *testing.T) {
		data := `{
			"@context": "https://www.w3.org/ns/did/v1.1",
			"id": "did:example:123",
			"authentication": [{
				"id": "did:example:123#key-1",
				"type": "Multikey",
				"controller": "did:example:123",
				"publicKeyMultibase": "zABC"
			}],
			"assertionMethod": [{
				"id": "did:example:123#key-1",
				"type": "Multikey",
				"controller": "did:example:123",
				"publicKeyMultibase": "zABC"
			}]
		}`
		var doc document.Document
		err := json.Unmarshal([]byte(data), &doc)
		require.NoError(t, err)
		require.Len(t, doc.VerificationMethods.All(), 1, "identical duplicate should appear once")
		require.Equal(t, "did:example:123#key-1", doc.Authentication.Get(0).String())
		require.Equal(t, "did:example:123#key-1", doc.AssertionMethod.Get(0).String())
	})

	t.Run("conflicting definitions for same ID", func(t *testing.T) {
		data := `{
			"@context": "https://www.w3.org/ns/did/v1.1",
			"id": "did:example:123",
			"authentication": [{
				"id": "did:example:123#key-1",
				"type": "Multikey",
				"controller": "did:example:123",
				"publicKeyMultibase": "zABC"
			}],
			"assertionMethod": [{
				"id": "did:example:123#key-1",
				"type": "Multikey",
				"controller": "did:example:123",
				"publicKeyMultibase": "zDIFFERENT"
			}]
		}`
		var doc document.Document
		err := json.Unmarshal([]byte(data), &doc)
		require.ErrorContains(t, err, `conflicting definitions for verification method "did:example:123#key-1"`)
	})
}
