package policy

import (
	"bytes"
	"errors"

	"github.com/fil-forge/ucantone/ucan"
	pdm "github.com/fil-forge/ucantone/ucan/delegation/policy/datamodel"
	cbg "github.com/whyrusleeping/cbor-gen"
)

const MatchErrorName = "MatchError"

func NewMatchError(statement ucan.Statement, err error) pdm.MatchErrorModel {
	var s cbg.Deferred
	if cms, ok := statement.(cbg.CBORMarshaler); ok {
		var b bytes.Buffer
		_ = cms.MarshalCBOR(&b)
		s.Raw = b.Bytes()
	}

	var c cbg.Deferred
	cause := errors.Unwrap(err)
	if cause != nil {
		if cmc, ok := cause.(cbg.CBORMarshaler); ok {
			var b bytes.Buffer
			_ = cmc.MarshalCBOR(&b)
			c.Raw = b.Bytes()
		}
	}

	return pdm.MatchErrorModel{
		ErrorName: MatchErrorName,
		Message:   err.Error(),
		Statement: &s,
		Cause:     &c,
	}
}
