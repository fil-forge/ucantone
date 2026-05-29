package key_test

import (
	"encoding/json"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/stretchr/testify/require"
)

func TestResolve(t *testing.T) {
	did, err := did.Parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
	require.NoError(t, err)
	doc, err := key.Resolve(t.Context(), did)
	require.NoError(t, err)

	docStr, err := json.Marshal(doc)
	require.NoError(t, err)

	// Example from https://w3c-ccg.github.io/did-key-spec/#create
	// * Note that the `enableEncryptionKeyDerivation` option is not currently
	//   supported and treated as false, so `keyAgreement` is omitted.
	// * Also note that the `@context` is normalized to a single string, which is
	//   equivalent.
	require.JSONEq(t, `{
		"@context": "https://www.w3.org/ns/did/v1.1",
		"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		"verificationMethod": [{
			"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			"type": "Multikey",
			"controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			"publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
		}],
		"authentication": [
			"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
		],
		"assertionMethod": [
			"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
		],
		"capabilityDelegation": [
			"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
		],
		"capabilityInvocation": [
			"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
		]
	}`, string(docStr))
}
