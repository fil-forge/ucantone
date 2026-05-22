package main

import (
	"github.com/fil-forge/ucantone/ucan/delegation/policy/fieldgen"
	"github.com/fil-forge/ucantone/ucan/delegation/policy/policytest"
)

func main() {
	if err := fieldgen.WriteFieldDescriptors("../fields/policy_fields_gen.go", "fields",
		policytest.Blob{},
		policytest.RetrieveArgs{},
		policytest.Shard{},
		policytest.Manifest{},
		policytest.SignArgs{},
		policytest.Envelope{},
		policytest.Tagged{},
		policytest.Labels{},
		policytest.Bundle{},
	); err != nil {
		panic(err)
	}
}
