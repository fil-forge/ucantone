package main

import (
	jsg "github.com/alanshaw/dag-json-gen"
	ddm "github.com/fil-forge/ucantone/ucan/delegation/datamodel"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	if err := cbg.WriteMapEncodersToFile("../cbor_gen.maps.go", "datamodel",
		ddm.TokenPayloadModel1_0_0_rc1{},
		ddm.SigPayloadModel{},
	); err != nil {
		panic(err)
	}
	if err := jsg.WriteMapEncodersToFile("../dag_json_gen.maps.go", "datamodel",
		ddm.TokenPayloadModel1_0_0_rc1{},
		ddm.SigPayloadModel{},
	); err != nil {
		panic(err)
	}
}
