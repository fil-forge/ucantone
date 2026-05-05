package main

import (
	jsg "github.com/alanshaw/dag-json-gen"
	pdm "github.com/fil-forge/ucantone/ucan/delegation/policy/datamodel"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	if err := cbg.WriteTupleEncodersToFile("../cbor_gen.go", "datamodel",
		pdm.PolicyModel{},
		pdm.ComparisonModel{},
		pdm.WildcardModel{},
		pdm.ConjunctionModel{},
		pdm.DisjunctionModel{},
		pdm.NegationModel{},
		pdm.QuantificationModel{},
	); err != nil {
		panic(err)
	}
	if err := jsg.WriteTupleEncodersToFile("../dag_json_gen.go", "datamodel",
		pdm.PolicyModel{},
		pdm.ComparisonModel{},
		pdm.WildcardModel{},
		pdm.ConjunctionModel{},
		pdm.DisjunctionModel{},
		pdm.NegationModel{},
		pdm.QuantificationModel{},
	); err != nil {
		panic(err)
	}
}
