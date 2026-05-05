package capability

import (
	"fmt"

	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/ucan"
)

const MalformedArgumentsErrorName = "MalformedArguments"

func NewMalformedArgumentsError(cmd ucan.Command, cause error) edm.ErrorModel {
	return edm.ErrorModel{
		ErrorName: MalformedArgumentsErrorName,
		Message:   fmt.Sprintf("malformed arguments for command %s: %s", cmd, cause.Error()),
	}
}
