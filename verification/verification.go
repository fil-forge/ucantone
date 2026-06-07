package verification

import (
	"context"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
)

// Factory is a function that produces a [ucan.Verifier] from
// [did.VerificationMaterial] for a specific verification method type.
type Factory func(context.Context, did.VerificationMaterial) (ucan.Verifier, error)

// ErrNoVerifierFactory is returned when no factory is registered for a
// verification method's type. Callers that want to skip unsupported VM types
// rather than fail should check for this error.
var ErrNoVerifierFactory = fmt.Errorf("no verifier factory registered")
