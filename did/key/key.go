package key

import (
	"context"

	"github.com/fil-forge/ucantone/did"
)

const Method = "key"

var Resolver did.ResolverFunc = resolve

// https://w3c-ccg.github.io/did-key-spec/#read
func resolve(_ context.Context, d did.DID) (did.Document, error) {
	if err := did.ValidateMethod(d, Method); err != nil {
		return did.Document{}, err
	}

	doc := did.NewDocument(d)
	vm := did.VerificationMethod{
		ID:         doc.Fragment(d.Identifier()),
		Controller: d,
		Type:       did.MultikeyVerificationMethodType,
		Material:   did.GenericMap{did.MultikeyPublicKeyMultibaseProp: d.Identifier()},
	}

	if err := doc.VerificationMethods.Add(vm); err != nil {
		return did.Document{}, err
	}

	if err := doc.Authentication.Add(vm); err != nil {
		return did.Document{}, err
	}
	if err := doc.AssertionMethod.Add(vm); err != nil {
		return did.Document{}, err
	}
	if err := doc.CapabilityDelegation.Add(vm); err != nil {
		return did.Document{}, err
	}
	if err := doc.CapabilityInvocation.Add(vm); err != nil {
		return did.Document{}, err
	}

	return doc, nil
}
