package bindexec

import (
	"fmt"

	edm "github.com/fil-forge/ucantone/errors/datamodel"
)

const MalformedArgumentsErrorName = "MalformedArguments"

func NewMalformedArgumentsError(cause error) error {
	return edm.ErrorModel{
		ErrorName: MalformedArgumentsErrorName,
		Message:   fmt.Sprintf("malformed arguments: %s", cause.Error()),
	}
}
