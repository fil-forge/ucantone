package datamodel

import (
	"fmt"
	"io"
)

type ErrorModel struct {
	ErrorName string `cborgen:"name"`
	Message   string `cborgen:"message"`
}

func (em ErrorModel) Name() string {
	return em.ErrorName
}

func (em ErrorModel) Error() string {
	return em.Message
}

var _ error = (*ErrorModel)(nil)

type ErrorModelWithCause struct {
	ErrorName string
	Message   string
	Cause     error
}

func (emc ErrorModelWithCause) Name() string {
	return emc.ErrorName
}

func (emc ErrorModelWithCause) Error() string {
	if emc.Cause == nil {
		return emc.Message
	}
	return fmt.Sprintf("%s: %s", emc.Message, emc.Cause.Error())
}

func (emc ErrorModelWithCause) Unwrap() error {
	return emc.Cause
}

func (emc ErrorModelWithCause) MarshalCBOR(w io.Writer) error {
	em := ErrorModel{
		ErrorName: emc.ErrorName,
		Message:   emc.Error(),
	}
	return em.MarshalCBOR(w)
}

var _ error = (*ErrorModelWithCause)(nil)
