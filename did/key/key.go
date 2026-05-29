package key

import (
	"context"

	"github.com/fil-forge/ucantone/did"
)

var Resolve did.ResolverFunc = resolve

func resolve(_ context.Context, d did.DID) (did.Document, error) {
	doc := did.NewDocument(d)
	vm := did.NewMultikeyVerificationMethod(
		doc.Fragment(d.Identifier()),
		d,
		d.Identifier(),
	)

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
