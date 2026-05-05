package dispatcher

import (
	"fmt"

	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/ucan"
)

const HandlerNotFoundErrorName = "HandlerNotFound"

func NewHandlerNotFoundError(cmd ucan.Command) error {
	return edm.ErrorModel{
		ErrorName: HandlerNotFoundErrorName,
		Message:   fmt.Sprintf("handler not found: %q", cmd),
	}
}
