package did_test

import (
	"encoding/json"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

type TestMaterial struct {
	Foo string `json:"foo"`
}

func (m *TestMaterial) Type() string {
	return "TestType"
}

func (m *TestMaterial) String() string {
	return "TestType: " + m.Foo
}

func TestVerificationMethod_MarshalJSON(t *testing.T) {
	keyID, err := did.ParseURL("did:example:123#key-1")
	require.NoError(t, err)
	controller, err := did.Parse("did:example:123")
	require.NoError(t, err)

	t.Run("Multikey", func(t *testing.T) {
		vm := did.NewMultikeyVerificationMethod(keyID, controller, "zABC")
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
		jwk := did.GenericMap{"kty": "OKP", "crv": "Ed25519", "x": "somebase64"}
		vm := did.NewJsonWebKeyVerificationMethod(keyID, controller, jwk)
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
	t.Run("known type (Multikey)", func(t *testing.T) {
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
		require.Equal(t, "Multikey", vm.Type())
		require.Equal(t, "did:example:123", vm.Controller.String())
		material, ok := vm.VerificationMaterial.(*did.MultikeyVerificationMaterial)
		require.True(t, ok, "expected *MultikeyVerificationMaterial, got %T", vm.VerificationMaterial)
		require.Equal(t, "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV", *material.PublicKeyMultibase)
		require.Nil(t, material.SecretKeyMultibase)
	})

	t.Run("known type (JsonWebKey)", func(t *testing.T) {
		data := `{
			"id": "did:example:123#key-2",
			"type": "JsonWebKey",
			"controller": "did:example:123",
			"publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "somebase64"}
		}`
		var vm did.VerificationMethod
		err := json.Unmarshal([]byte(data), &vm)
		require.NoError(t, err)
		material, ok := vm.VerificationMaterial.(*did.JsonWebKeyVerificationMaterial)
		require.True(t, ok, "expected *JsonWebKeyVerificationMaterial, got %T", vm.VerificationMaterial)
		require.NotNil(t, material.PublicKeyJwk)
		require.Equal(t, "OKP", (*material.PublicKeyJwk)["kty"])
	})

	t.Run("unknown type falls back to GenericMap with extra fields only", func(t *testing.T) {
		data := `{
			"id": "did:example:123#key-3",
			"type": "SomeUnknownType",
			"controller": "did:example:123",
			"customField": "customValue"
		}`
		var vm did.VerificationMethod
		err := json.Unmarshal([]byte(data), &vm)
		require.NoError(t, err)
		require.Equal(t, "SomeUnknownType", vm.Type())
		gvm, ok := vm.VerificationMaterial.(*did.GenericVerificationMaterial)
		require.True(t, ok, "expected GenericMap, got %T", vm.VerificationMaterial)
		require.Equal(t, "customValue", gvm.Fields["customField"])
		require.NotContains(t, gvm.Fields, "id")
		require.NotContains(t, gvm.Fields, "type")
		require.NotContains(t, gvm.Fields, "controller")
	})

	t.Run("registered external type", func(t *testing.T) {
		did.RegisterVerificationMethodType(func() did.VerificationMaterial {
			return &TestMaterial{}
		})

		data := `{
			"id": "did:example:123#key-4",
			"type": "TestType",
			"controller": "did:example:123",
			"foo": "bar"
		}`
		var vm did.VerificationMethod
		err := json.Unmarshal([]byte(data), &vm)
		require.NoError(t, err)
		material, ok := vm.VerificationMaterial.(*TestMaterial)
		require.True(t, ok, "expected *TestMaterial, got %T", vm.VerificationMaterial)
		require.Equal(t, "bar", material.Foo)
	})
}
