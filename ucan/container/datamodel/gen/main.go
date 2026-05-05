package main

import (
	jsg "github.com/alanshaw/dag-json-gen"
	cdm "github.com/fil-forge/ucantone/ucan/container/datamodel"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	if err := cbg.WriteMapEncodersToFile("../cbor_gen.go", "datamodel",
		cdm.ContainerModel{},
	); err != nil {
		panic(err)
	}
	if err := jsg.WriteMapEncodersToFile("../dag_json_gen.go", "datamodel",
		cdm.ContainerModel{},
	); err != nil {
		panic(err)
	}
}
