package main

import (
	jsg "github.com/alanshaw/dag-json-gen"
	edm "github.com/fil-forge/ucantone/ucan/envelope/datamodel"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	if err := cbg.WriteTupleEncodersToFile("../cbor_gen.go", "datamodel",
		edm.EnvelopeModel{},
	); err != nil {
		panic(err)
	}
	if err := jsg.WriteTupleEncodersToFile("../dag_json_gen.go", "datamodel",
		edm.EnvelopeModel{},
	); err != nil {
		panic(err)
	}
}
