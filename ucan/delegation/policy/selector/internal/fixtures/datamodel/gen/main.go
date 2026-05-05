package main

import (
	jsg "github.com/alanshaw/dag-json-gen"
	"github.com/fil-forge/ucantone/ucan/delegation/policy/selector/internal/fixtures/datamodel"
)

func main() {
	if err := jsg.WriteMapEncodersToFile("../dag_json_gen.go", "datamodel",
		datamodel.FixtureModel{},
		datamodel.FixturesModel{},
	); err != nil {
		panic(err)
	}
}
