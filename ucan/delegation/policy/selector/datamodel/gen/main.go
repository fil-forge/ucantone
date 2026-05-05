package main

import (
	jsg "github.com/alanshaw/dag-json-gen"
	sdm "github.com/fil-forge/ucantone/ucan/delegation/policy/selector/datamodel"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	if err := cbg.WriteMapEncodersToFile("../cbor_gen.go", "datamodel",
		sdm.ParseErrorModel{},
		sdm.ResolutionErrorModel{},
	); err != nil {
		panic(err)
	}
	if err := jsg.WriteMapEncodersToFile("../dag_json_gen.go", "datamodel",
		sdm.ParseErrorModel{},
		sdm.ResolutionErrorModel{},
	); err != nil {
		panic(err)
	}
}
