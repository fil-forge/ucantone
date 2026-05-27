package document

import (
	"encoding/json"

	"github.com/fil-forge/ucantone/did"
)

// GenericMap is a value that is either specified to be a map with no particular
// set of keys, or whose spec is not currently implemented here.
type GenericMap = map[string]any

// https://www.w3.org/TR/did-1.1/#core-properties
type Document struct {
	Context              Context                  `json:"@context"`
	ID                   string                   `json:"id"`
	Controller           OneOrMany[did.DID]       `json:"controller,omitempty"`
	AlsoKnownAs          []did.DID                `json:"alsoKnownAs,omitempty"`
	Service              []Service                `json:"service,omitempty"`
	VerificationMethods  VerificationMethods      `json:"verificationMethod,omitempty"`
	Authentication       VerificationRelationship `json:"authentication,omitempty"`
	AssertionMethod      VerificationRelationship `json:"assertionMethod,omitempty"`
	KeyAgreement         VerificationRelationship `json:"keyAgreement,omitempty"`
	CapabilityInvocation VerificationRelationship `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation VerificationRelationship `json:"capabilityDelegation,omitempty"`
}

func (d *Document) UnmarshalJSON(b []byte) error {
	type documentJSON struct {
		Context              Context             `json:"@context"`
		ID                   string              `json:"id"`
		Controller           OneOrMany[did.DID]  `json:"controller,omitempty"`
		AlsoKnownAs          []did.DID           `json:"alsoKnownAs,omitempty"`
		Service              []Service           `json:"service,omitempty"`
		VerificationMethods  VerificationMethods `json:"verificationMethod,omitempty"`
		Authentication       json.RawMessage     `json:"authentication,omitempty"`
		AssertionMethod      json.RawMessage     `json:"assertionMethod,omitempty"`
		KeyAgreement         json.RawMessage     `json:"keyAgreement,omitempty"`
		CapabilityInvocation json.RawMessage     `json:"capabilityInvocation,omitempty"`
		CapabilityDelegation json.RawMessage     `json:"capabilityDelegation,omitempty"`
	}
	var raw documentJSON
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	d.Context = raw.Context
	d.ID = raw.ID
	d.Controller = raw.Controller
	d.AlsoKnownAs = raw.AlsoKnownAs
	d.Service = raw.Service
	d.VerificationMethods = raw.VerificationMethods

	for _, rel := range []struct {
		raw  json.RawMessage
		dest *VerificationRelationship
		name string
	}{
		{raw.Authentication, &d.Authentication, "authentication"},
		{raw.AssertionMethod, &d.AssertionMethod, "assertionMethod"},
		{raw.KeyAgreement, &d.KeyAgreement, "keyAgreement"},
		{raw.CapabilityInvocation, &d.CapabilityInvocation, "capabilityInvocation"},
		{raw.CapabilityDelegation, &d.CapabilityDelegation, "capabilityDelegation"},
	} {
		if len(rel.raw) == 0 {
			continue
		}
		rel.dest.allMethods = &d.VerificationMethods
		if err := json.Unmarshal(rel.raw, rel.dest); err != nil {
			return err
		}
	}
	return nil
}

// Services are not yet implemented.
type Service = GenericMap
