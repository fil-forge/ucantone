package document

import (
	"encoding/json"
	"errors"
)

type VerificationRelationship struct {
	allMethods          *VerificationMethods
	relationshipMethods []URL
}

// TK: Suspect; this should be a set
func (vr VerificationRelationship) Get(i int) URL {
	return vr.relationshipMethods[i]
}

func (vr VerificationRelationship) Len() int {
	return len(vr.relationshipMethods)
}

func (vr VerificationRelationship) IsZero() bool {
	return len(vr.relationshipMethods) == 0
}

func (vr VerificationRelationship) MarshalJSON() ([]byte, error) {
	return json.Marshal(vr.relationshipMethods)
}

func (vr *VerificationRelationship) UnmarshalJSON(data []byte) error {
	var raws []json.RawMessage
	err := json.Unmarshal(data, &raws)
	if err != nil {
		return err
	}

	for _, raw := range raws {
		var u URL
		err := json.Unmarshal(raw, &u)
		if err == nil {
			vr.relationshipMethods = append(vr.relationshipMethods, u)
			continue
		}
		var typeErr *json.UnmarshalTypeError
		if !errors.As(err, &typeErr) {
			return err
		}
		var vm VerificationMethod
		if err := json.Unmarshal(raw, &vm); err != nil {
			return err
		}
		if err := vr.allMethods.Add(vm); err != nil {
			return err
		}
		vr.relationshipMethods = append(vr.relationshipMethods, vm.ID)
	}
	return nil
}
