package main

import (
	jsg "github.com/alanshaw/dag-json-gen"
	edm "github.com/fil-forge/ucantone/errors/datamodel"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	if err := cbg.WriteMapEncodersToFile("../cbor_gen.go", "datamodel",
		edm.ErrorModel{},
	); err != nil {
		panic(err)
	}
	if err := jsg.WriteMapEncodersToFile("../dag_json_gen.go", "datamodel",
		edm.ErrorModel{},
	); err != nil {
		panic(err)
	}
}
