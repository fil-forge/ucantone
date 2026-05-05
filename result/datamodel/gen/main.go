package main

import (
	jsg "github.com/alanshaw/dag-json-gen"
	rdm "github.com/fil-forge/ucantone/result/datamodel"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	if err := cbg.WriteMapEncodersToFile("../cbor_gen.go", "datamodel",
		rdm.ResultModel{},
	); err != nil {
		panic(err)
	}
	if err := jsg.WriteMapEncodersToFile("../dag_json_gen.go", "datamodel",
		rdm.ResultModel{},
	); err != nil {
		panic(err)
	}
}
