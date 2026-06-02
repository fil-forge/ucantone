package did

import (
	"encoding/json"
)

// GenericMap is a value that is either specified to be a map with no particular
// set of keys, or whose spec is not currently implemented here.
type GenericMap = map[string]any

// VerificationMaterial is the type-specific material fields of a
// [VerificationMethod], keyed by field name.
// https://www.w3.org/TR/cid-1.0/#verification-material
type VerificationMaterial = GenericMap

// https://www.w3.org/TR/did-1.1/#core-properties
type Document struct {
	Context              Context                   `json:"@context"`
	ID                   DID                       `json:"id"`
	Controller           OneOrMany[DID]            `json:"controller,omitempty"`
	AlsoKnownAs          []DID                     `json:"alsoKnownAs,omitempty"`
	Service              []Service                 `json:"service,omitempty"`
	VerificationMethods  *VerificationMethods      `json:"verificationMethod,omitempty"`
	Authentication       *VerificationRelationship `json:"authentication,omitzero"`
	AssertionMethod      *VerificationRelationship `json:"assertionMethod,omitzero"`
	KeyAgreement         *VerificationRelationship `json:"keyAgreement,omitzero"`
	CapabilityInvocation *VerificationRelationship `json:"capabilityInvocation,omitzero"`
	CapabilityDelegation *VerificationRelationship `json:"capabilityDelegation,omitzero"`
}

func NewDocument(id DID) Document {
	vms := VerificationMethods{}
	return Document{
		ID:                   id,
		VerificationMethods:  &vms,
		Authentication:       &VerificationRelationship{allMethods: &vms},
		AssertionMethod:      &VerificationRelationship{allMethods: &vms},
		KeyAgreement:         &VerificationRelationship{allMethods: &vms},
		CapabilityInvocation: &VerificationRelationship{allMethods: &vms},
		CapabilityDelegation: &VerificationRelationship{allMethods: &vms},
	}
}

// Fragment returns a URL for the given fragment within this document, e.g. for
// a verification method.
func (d Document) Fragment(fragment string) URL {
	url, err := ParseURL(d.ID.String())
	if err != nil {
		// This should not be possible: a DID is always a valid URL. (Actually, it's
		// a valid *URI*, but that should work too.)
		panic("failed to create URL for DID: " + err.Error())
	}
	url.URL.Fragment = fragment
	return url
}

func (d *Document) UnmarshalJSON(b []byte) error {
	type documentJSON struct {
		Context              Context             `json:"@context"`
		ID                   string              `json:"id"`
		Controller           OneOrMany[DID]      `json:"controller,omitempty"`
		AlsoKnownAs          []DID               `json:"alsoKnownAs,omitempty"`
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
	var err error
	d.ID, err = Parse(raw.ID)
	if err != nil {
		return err
	}
	d.Controller = raw.Controller
	d.AlsoKnownAs = raw.AlsoKnownAs
	d.Service = raw.Service
	d.VerificationMethods = &raw.VerificationMethods

	d.Authentication = &VerificationRelationship{allMethods: d.VerificationMethods}
	d.AssertionMethod = &VerificationRelationship{allMethods: d.VerificationMethods}
	d.KeyAgreement = &VerificationRelationship{allMethods: d.VerificationMethods}
	d.CapabilityInvocation = &VerificationRelationship{allMethods: d.VerificationMethods}
	d.CapabilityDelegation = &VerificationRelationship{allMethods: d.VerificationMethods}

	for _, rel := range []struct {
		raw  json.RawMessage
		dest **VerificationRelationship
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
		(*rel.dest).allMethods = d.VerificationMethods
		if err := json.Unmarshal(rel.raw, *rel.dest); err != nil {
			return err
		}
	}
	return nil
}

// Services are not yet implemented.
type Service = GenericMap
