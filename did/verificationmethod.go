package did

import (
	"encoding/json"
	"reflect"
	"strings"
)

// VerificationMaterial holds the type-specific material for a
// VerificationMethod.
type VerificationMaterial any

var vmRegistry = map[string]func() VerificationMaterial{}

// RegisterVerificationMethodType registers a factory function for a given
// verification method type name.
func RegisterVerificationMethodType(typeName string, factory func() VerificationMaterial) {
	vmRegistry[typeName] = factory
}

func init() {
	RegisterVerificationMethodType(MultikeyVerificationMethodType, func() VerificationMaterial {
		return &MultikeyVerificationMaterial{}
	})
	RegisterVerificationMethodType(JsonWebKeyVerificationMethodType, func() VerificationMaterial {
		return &JsonWebKeyVerificationMaterial{}
	})
}

// https://www.w3.org/TR/cid-1.0/#verification-methods
type VerificationMethod struct {
	ID                   URL                  `json:"id"`
	Type                 string               `json:"type"`
	Controller           DID                  `json:"controller"`
	Expires              *DateTimeStamp       `json:"expires,omitempty"`
	Revoked              *DateTimeStamp       `json:"revoked,omitempty"`
	VerificationMaterial VerificationMaterial `json:"-"`
}

func (v VerificationMethod) Equal(other VerificationMethod) bool {
	if v.ID.String() != other.ID.String() || v.Type != other.Type || v.Controller != other.Controller {
		return false
	}
	if (v.Expires == nil) != (other.Expires == nil) || (v.Revoked == nil) != (other.Revoked == nil) {
		return false
	}
	if v.Expires != nil && *v.Expires != *other.Expires {
		return false
	}
	if v.Revoked != nil && *v.Revoked != *other.Revoked {
		return false
	}
	return reflect.DeepEqual(v.VerificationMaterial, other.VerificationMaterial)
}

var vmBaseKeys = jsonTagKeys(VerificationMethod{})

func jsonTagKeys(v any) []string {
	t := reflect.TypeOf(v)
	keys := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		if tag := t.Field(i).Tag.Get("json"); tag != "" {
			keys = append(keys, strings.SplitN(tag, ",", 2)[0])
		}
	}
	return keys
}

func (v *VerificationMethod) UnmarshalJSON(b []byte) error {
	type vm VerificationMethod
	var base vm
	if err := json.Unmarshal(b, &base); err != nil {
		return err
	}
	*v = VerificationMethod(base)

	// Unmarshal all fields into a raw map, strip base keys, pass extras to material.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for _, k := range vmBaseKeys {
		delete(raw, k)
	}
	extraJSON, err := json.Marshal(raw)
	if err != nil {
		return err
	}

	if factory, ok := vmRegistry[v.Type]; ok {
		material := factory()
		if err := json.Unmarshal(extraJSON, material); err != nil {
			return err
		}
		v.VerificationMaterial = material
	} else {
		gm := make(GenericMap)
		if err := json.Unmarshal(extraJSON, &gm); err != nil {
			return err
		}
		v.VerificationMaterial = gm
	}
	return nil
}

func (v VerificationMethod) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}

	// Marshal material fields first so base fields win on collision.
	if v.VerificationMaterial != nil {
		materialJSON, err := json.Marshal(v.VerificationMaterial)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(materialJSON, &out); err != nil {
			return nil, err
		}
	}

	type vm VerificationMethod
	baseJSON, err := json.Marshal(vm(v))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(baseJSON, &out); err != nil {
		return nil, err
	}

	return json.Marshal(out)
}

func NewMultikeyVerificationMethod(id URL, controller DID, publicKeyMultibase string) VerificationMethod {
	return VerificationMethod{
		ID:         id,
		Type:       MultikeyVerificationMethodType,
		Controller: controller,
		VerificationMaterial: &MultikeyVerificationMaterial{
			PublicKeyMultibase: &publicKeyMultibase,
		},
	}
}

func NewJsonWebKeyVerificationMethod(id URL, controller DID, publicKeyJwk GenericMap) VerificationMethod {
	return VerificationMethod{
		ID:         id,
		Type:       JsonWebKeyVerificationMethodType,
		Controller: controller,
		VerificationMaterial: &JsonWebKeyVerificationMaterial{
			PublicKeyJwk: &publicKeyJwk,
		},
	}
}

// https://www.w3.org/TR/cid-1.0/#Multikey
const MultikeyVerificationMethodType = "Multikey"

type MultikeyVerificationMaterial struct {
	PublicKeyMultibase *string `json:"publicKeyMultibase"`
	SecretKeyMultibase *string `json:"secretKeyMultibase,omitempty"`
}

// https://www.w3.org/TR/cid-1.0/#JsonWebKey
const JsonWebKeyVerificationMethodType = "JsonWebKey"

type JsonWebKeyVerificationMaterial struct {
	PublicKeyJwk *GenericMap `json:"publicKeyJwk"`
	SecretKeyJwk *GenericMap `json:"secretKeyJwk,omitempty"`
}

// JWK is not yet implemented.
type JsonWebKey = GenericMap
