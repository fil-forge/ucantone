package datamodel

import (
	"github.com/fil-forge/ucantone/ipld/datamodel"
)

// ResultModel is the wire encoding of a UCAN [result.Result]: either an Ok
// or an Err branch, each holding a raw CBOR-encoded payload. Consumers
// decode the bytes into a typed cborgen struct that matches the schema
// expected for the receipt's command.
type ResultModel struct {
	Ok  *datamodel.Raw `cborgen:"ok,omitempty"`
	Err *datamodel.Raw `cborgen:"error,omitempty"`
}
