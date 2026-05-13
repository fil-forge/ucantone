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

const InvalidAudienceErrorName = "InvalidAudience"

func NewInvalidAudienceError(expected did.DID, actual did.DID) error {
	return edm.ErrorModel{
		ErrorName: InvalidAudienceErrorName,
		Message:   fmt.Errorf("invalid audience: expected %q, got %q", expected, actual).Error(),
	}
}
