package binding

import (
	"fmt"

	edm "github.com/fil-forge/ucantone/errors/datamodel"
)

// MalformedArgumentsErrorName is the error name reported in a receipt when an
// invocation's arguments cannot be decoded into the command's Args type.
const MalformedArgumentsErrorName = "MalformedArguments"

// NewMalformedArgumentsError builds the error a handler returns when argument
// decoding fails; see [NewHandler], which reports it automatically.
func NewMalformedArgumentsError(cause error) error {
	return edm.ErrorModel{
		ErrorName: MalformedArgumentsErrorName,
		Message:   fmt.Sprintf("malformed arguments: %s", cause.Error()),
	}
}
