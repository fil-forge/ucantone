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

const ExecutionFailureErrorName = "ExecutionFailure"

// NewExecutionFailureError is the failure a receipt carries when executing the
// invocation panicked, in the handler or in validation code such as a DID
// resolver or verifier factory. The receipt says only that execution failed;
// the panic value and the fact that it was a panic stay on the server.
func NewExecutionFailureError(cmd ucan.Command) error {
	return edm.ErrorModel{
		ErrorName: ExecutionFailureErrorName,
		Message:   fmt.Sprintf("%q execution failed", cmd),
	}
}

const InvalidAudienceErrorName = "InvalidAudience"

func NewInvalidAudienceError(expected did.DID, actual did.DID) error {
	return edm.ErrorModel{
		ErrorName: InvalidAudienceErrorName,
		Message:   fmt.Errorf("invalid audience: expected %q, got %q", expected, actual).Error(),
	}
}
