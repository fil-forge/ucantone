package verification

import (
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
)

var registry = map[string]func(did.VerificationMaterial) (ucan.Verifier, error){}

// RegisterVerifierFactory registers a factory function for a given
// verification method type name. When DeriveVerifier is called with a
// VerificationMethod of that type, the factory is called with its Material.
func RegisterVerifierFactory(vmType string, f func(did.VerificationMaterial) (ucan.Verifier, error)) {
	registry[vmType] = f
}

// ErrNoVerifierFactory is returned by DeriveVerifier when no factory is
// registered for the verification method's type. Callers that want to skip
// unsupported VM types rather than fail should check for this error.
var ErrNoVerifierFactory = fmt.Errorf("no verifier factory registered")

// DeriveVerifier produces a [ucan.Verifier] from a [did.VerificationMethod]
// using the registered factory for its type. If no factory is registered for
// the VM type, it returns [ErrNoVerifierFactory].
func DeriveVerifier(vm did.VerificationMethod) (ucan.Verifier, error) {
	f, ok := registry[vm.Type]
	if !ok {
		return nil, fmt.Errorf("%w for VM type %q", ErrNoVerifierFactory, vm.Type)
	}
	return f(vm.Material)
}
