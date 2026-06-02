package verification

import (
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
)

var registry = map[string]func(did.VerificationMethod) (ucan.Verifier, error){}

// RegisterVerifierFactory registers a factory function for a given
// verification method type name. When DeriveVerifier is called with a
// VerificationMethod of that type, the factory is used to produce a Verifier.
func RegisterVerifierFactory(vmType string, f func(did.VerificationMethod) (ucan.Verifier, error)) {
	registry[vmType] = f
}

// DeriveVerifier produces a [ucan.Verifier] from a [did.VerificationMethod]
// using the registered factory for its type.
func DeriveVerifier(vm did.VerificationMethod) (ucan.Verifier, error) {
	f, ok := registry[vm.Type]
	if !ok {
		return nil, fmt.Errorf("no verifier registered for VM type %q", vm.Type)
	}
	return f(vm)
}
