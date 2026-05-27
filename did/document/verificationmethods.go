package document

import (
	"encoding/json"
	"fmt"
)

type VerificationMethods map[string]VerificationMethod

func (vms *VerificationMethods) Add(vm VerificationMethod) error {
	if *vms == nil {
		*vms = make(VerificationMethods)
	}
	if existing, ok := (*vms)[vm.ID.String()]; ok {
		if !existing.Equal(vm) {
			return fmt.Errorf("conflicting definitions for verification method %q", vm.ID.String())
		}
		return nil
	}
	(*vms)[vm.ID.String()] = vm
	return nil
}

func (v *VerificationMethods) All() []VerificationMethod {
	var all []VerificationMethod
	for _, vm := range *v {
		all = append(all, vm)
	}
	return all
}

func (vms VerificationMethods) MarshalJSON() ([]byte, error) {
	methods := make([]VerificationMethod, 0, len(vms))
	for _, vm := range vms {
		methods = append(methods, vm)
	}
	return json.Marshal(methods)
}

func (v *VerificationMethods) UnmarshalJSON(b []byte) error {
	var vms []VerificationMethod
	err := json.Unmarshal(b, &vms)
	if err != nil {
		return err
	}
	for _, vm := range vms {
		if err := v.Add(vm); err != nil {
			return err
		}
	}
	return nil
}
