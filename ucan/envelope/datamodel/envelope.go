package datamodel

import (
	idm "github.com/fil-forge/ucantone/ipld/datamodel"
)

// EnvelopeModel is the canonical UCAN envelope: a tuple of the signature
// over the SigPayload and the SigPayload bytes themselves.
//
// The SigPayload is held as canonical CBOR bytes ([idm.Raw]) so that signature
// verification can operate on the literal bytes the issuer signed, without
// re-encoding through a typed Go representation. Consumers decode SigPayload
// into a sub-spec-specific typed model (e.g. invocation.SigPayloadModel) only
// when they need to read the structured fields.
//
// Per the UCAN spec: "All UCANs MUST be canonically encoded with DAG-CBOR for
// signing. A UCAN MAY be presented or stored in other IPLD formats (such as
// DAG-JSON), but converted to DAG-CBOR for signature validation."
type EnvelopeModel struct {
	Signature  []byte
	SigPayload idm.Raw
}
