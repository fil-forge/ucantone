package did_test

import (
	"encoding/json"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

func TestVerificationMethod_MarshalJSON(t *testing.T) {
	keyID, err := did.ParseURL("did:example:123#key-1")
	require.NoError(t, err)
	controller, err := did.Parse("did:example:123")
	require.NoError(t, err)

	t.Run("Multikey", func(t *testing.T) {
		vm := did.VerificationMethod{
			ID:         keyID,
			Controller: controller,
			Type:       did.MultikeyVerificationMethodType,
			Material:   did.GenericMap{did.MultikeyPublicKeyMultibaseProp: "zABC"},
		}
		b, err := json.Marshal(vm)
		require.NoError(t, err)
		require.JSONEq(t, `{
			"id": "did:example:123#key-1",
			"type": "Multikey",
			"controller": "did:example:123",
			"publicKeyMultibase": "zABC"
		}`, string(b))
	})

	t.Run("JsonWebKey", func(t *testing.T) {
		vm := did.VerificationMethod{
			ID:         keyID,
			Controller: controller,
			Type:       did.JsonWebKeyVerificationMethodType,
			Material:   did.GenericMap{did.JsonWebKeyPublicKeyJwkProp: did.GenericMap{"kty": "OKP", "crv": "Ed25519", "x": "somebase64"}},
		}
		b, err := json.Marshal(vm)
		require.NoError(t, err)
		require.JSONEq(t, `{
			"id": "did:example:123#key-1",
			"type": "JsonWebKey",
			"controller": "did:example:123",
			"publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "somebase64"}
		}`, string(b))
	})
}

func TestVerificationMethod_UnmarshalJSON(t *testing.T) {
	t.Run("Multikey", func(t *testing.T) {
		data := `{
			"id": "did:example:123#key-1",
			"type": "Multikey",
			"controller": "did:example:123",
			"publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
		}`
		var vm did.VerificationMethod
		err := json.Unmarshal([]byte(data), &vm)
		require.NoError(t, err)
		require.Equal(t, "did:example:123#key-1", vm.ID.String())
		require.Equal(t, did.MultikeyVerificationMethodType, vm.Type)
		require.Equal(t, "did:example:123", vm.Controller.String())
		require.Equal(t, "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV", vm.Material[did.MultikeyPublicKeyMultibaseProp])
	})

	t.Run("JsonWebKey", func(t *testing.T) {
		data := `{
			"id": "did:example:123#key-2",
			"type": "JsonWebKey",
			"controller": "did:example:123",
			"publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "somebase64"}
		}`
		var vm did.VerificationMethod
		err := json.Unmarshal([]byte(data), &vm)
		require.NoError(t, err)
		require.Equal(t, did.JsonWebKeyVerificationMethodType, vm.Type)
		jwk, ok := vm.Material[did.JsonWebKeyPublicKeyJwkProp].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "OKP", jwk["kty"])
	})

	t.Run("unknown type", func(t *testing.T) {
		data := `{
			"id": "did:example:123#key-3",
			"type": "SomeUnknownType",
			"controller": "did:example:123",
			"customField": "customValue"
		}`
		var vm did.VerificationMethod
		err := json.Unmarshal([]byte(data), &vm)
		require.NoError(t, err)
		require.Equal(t, "SomeUnknownType", vm.Type)
		require.Equal(t, "customValue", vm.Material["customField"])
		require.NotContains(t, vm.Material, "id")
		require.NotContains(t, vm.Material, "type")
		require.NotContains(t, vm.Material, "controller")
	})
}
