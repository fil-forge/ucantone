package errors

import (
	"errors"

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

func New(name, message string) error {
	return edm.ErrorModel{
		ErrorName: name,
		Message:   message,
	}
}
