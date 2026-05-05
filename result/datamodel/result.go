package datamodel

import (
	"github.com/fil-forge/ucantone/ipld/datamodel"
)

type ResultModel struct {
	Ok  *datamodel.Any `cborgen:"ok,omitempty"`
	Err *datamodel.Any `cborgen:"error,omitempty"`
}
