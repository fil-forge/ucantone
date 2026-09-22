package execution

import (
	"fmt"

	"github.com/fil-forge/ucantone/did"
	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/ucan"
)

const HandlerExecutionErrorName = "HandlerExecutionError"

func NewHandlerExecutionError(cmd ucan.Command, cause error) error {
	return edm.ErrorModel{
		ErrorName: HandlerExecutionErrorName,
		Message:   fmt.Errorf("%q handler execution error: %w", cmd, cause).Error(),
	}
}

const ExecutionPanicErrorName = "ExecutionPanicError"

// NewExecutionPanicError is the failure a receipt carries when executing the
// invocation panicked outside the handler, in validation code such as a DID
// resolver or verifier factory. The panic value stays on the server.
func NewExecutionPanicError(cmd ucan.Command) error {
	return edm.ErrorModel{
		ErrorName: ExecutionPanicErrorName,
		Message:   fmt.Sprintf("%q execution panicked", cmd),
	}
}

const InvalidAudienceErrorName = "InvalidAudience"

func NewInvalidAudienceError(expected did.DID, actual did.DID) error {
	return edm.ErrorModel{
		ErrorName: InvalidAudienceErrorName,
		Message:   fmt.Errorf("invalid audience: expected %q, got %q", expected, actual).Error(),
	}
}
