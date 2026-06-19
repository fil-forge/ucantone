package did

import (
	"encoding/json"
	"fmt"
	"time"
)

// https://www.w3.org/TR/cid-1.0/#verification-methods
type VerificationMethod struct {
	ID         URL            `json:"id"`
	Controller DID            `json:"controller"`
	Expires    *DateTimeStamp `json:"expires,omitempty"`
	Revoked    *DateTimeStamp `json:"revoked,omitempty"`
	Type       string
	Material   GenericMap
}

// ValidAt reports whether the verification method is valid at time t.
func (v VerificationMethod) ValidAt(t time.Time) bool {
	return !v.ExpiredAt(t) && !v.RevokedAt(t)
}

// ExpiredAt reports whether the verification method is expired at time t.
func (v VerificationMethod) ExpiredAt(t time.Time) bool {
	if v.Expires != nil && !t.Before(v.Expires.Time()) {
		return true
	}
	return false
}

// RevokedAt reports whether the verification method is revoked at time t.
func (v VerificationMethod) RevokedAt(t time.Time) bool {
	if v.Revoked != nil && !t.Before(v.Revoked.Time()) {
		return true
	}
	return false
}

func (v VerificationMethod) String() string {
	return fmt.Sprintf("VerificationMethod{id=%s, type=%s, controller=%s, expires=%v, revoked=%v, material=%v}",
		v.ID, v.Type, v.Controller, v.Expires, v.Revoked, v.Material)
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
	if len(v.Material) != len(other.Material) {
		return false
	}
	for k, val := range v.Material {
		if other.Material[k] != val {
			return false
		}
	}
	return true
}

type vmBase struct {
	ID         URL            `json:"id"`
	Controller DID            `json:"controller"`
	Expires    *DateTimeStamp `json:"expires,omitempty"`
	Revoked    *DateTimeStamp `json:"revoked,omitempty"`
}

func (v *VerificationMethod) UnmarshalJSON(b []byte) error {
	var base vmBase
	if err := json.Unmarshal(b, &base); err != nil {
		return err
	}
	v.ID = base.ID
	v.Controller = base.Controller
	v.Expires = base.Expires
	v.Revoked = base.Revoked

	// Unmarshal all fields into a raw map, strip base keys and "type",
	// leaving only the verification material fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for _, k := range []string{"id", "controller", "expires", "revoked"} {
		delete(raw, k)
	}

	if err := json.Unmarshal(raw["type"], &v.Type); err != nil {
		return err
	}
	delete(raw, "type")

	extraJSON, err := json.Marshal(raw)
	if err != nil {
		return err
	}

	return json.Unmarshal(extraJSON, &v.Material)
}

func (v VerificationMethod) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}

	// Marshal material fields first so base fields win on collision.
	if v.Material != nil {
		materialJSON, err := json.Marshal(v.Material)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(materialJSON, &out); err != nil {
			return nil, err
		}
	}

	var err error
	out["type"], err = json.Marshal(v.Type)
	if err != nil {
		return nil, err
	}

	baseJSON, err := json.Marshal(vmBase{v.ID, v.Controller, v.Expires, v.Revoked})
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(baseJSON, &out); err != nil {
		return nil, err
	}

	return json.Marshal(out)
}
