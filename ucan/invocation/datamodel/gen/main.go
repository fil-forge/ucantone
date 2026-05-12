package main

import (
	jsg "github.com/alanshaw/dag-json-gen"
	idm "github.com/fil-forge/ucantone/ucan/invocation/datamodel"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	if err := cbg.WriteMapEncodersToFile("../cbor_gen.maps.go", "datamodel",
		idm.TaskModel{},
		idm.TokenPayloadModel1_0_0_rc1{},
		idm.SigPayloadModel{},
	); err != nil {
		panic(err)
	}
	if err := jsg.WriteMapEncodersToFile("../dag_json_gen.maps.go", "datamodel",
		idm.TaskModel{},
		idm.TokenPayloadModel1_0_0_rc1{},
		idm.SigPayloadModel{},
	); err != nil {
		panic(err)
	}
}
