package main

import (
	jsg "github.com/alanshaw/dag-json-gen"
	rdm "github.com/fil-forge/ucantone/ucan/receipt/datamodel"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	if err := cbg.WriteMapEncodersToFile("../cbor_gen.go", "datamodel",
		rdm.ArgsModel{},
	); err != nil {
		panic(err)
	}
	if err := jsg.WriteMapEncodersToFile("../dsg_json_gen.go", "datamodel",
		rdm.ArgsModel{},
	); err != nil {
		panic(err)
	}
}
