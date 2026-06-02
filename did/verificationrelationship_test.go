package did_test

import (
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

func TestVerificationRelationship_Add(t *testing.T) {
	d, err := did.Parse("did:example:123456789abcdefghi")
	require.NoError(t, err)
	doc := did.NewDocument(d)
	vm := did.VerificationMethod{
		ID:         doc.Fragment("key-1"),
		Controller: d,
		Type:       did.MultikeyVerificationMethodType,
		Material:   did.GenericMap{did.MultikeyPublicKeyMultibase: "zABC"},
	}
	err = doc.VerificationMethods.Add(vm)
	require.NoError(t, err)

	require.Equal(t, 0, doc.Authentication.Len())

	err = doc.Authentication.Add(vm)
	require.NoError(t, err)
	require.Equal(t, 1, doc.Authentication.Len())

	var authVMIds []string
	for _, authVM := range doc.Authentication.All() {
		authVMIds = append(authVMIds, authVM.ID.String())
	}
	require.Equal(t, []string{vm.ID.String()}, authVMIds)
}
