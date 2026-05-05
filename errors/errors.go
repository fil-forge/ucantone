package errors

import (
	"errors"
	"fmt"

	edm "github.com/fil-forge/ucantone/errors/datamodel"
)

var (
	Is   = errors.Is
	As   = errors.As
	Join = errors.Join
)

type Named interface {
	error
	Name() string
}

func New(name, message string, args ...any) error {
	if len(args) > 0 {
		message = fmt.Sprintf(message, args...)
	}
	return edm.ErrorModel{
		ErrorName: name,
		Message:   message,
	}
}
