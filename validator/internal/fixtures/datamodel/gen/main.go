package main

import (
	jsg "github.com/alanshaw/dag-json-gen"
	"github.com/fil-forge/ucantone/validator/internal/fixtures/datamodel"
)

func main() {
	if err := jsg.WriteMapEncodersToFile("../dag_json_gen.go", "datamodel",
		datamodel.ErrorModel{},
		datamodel.FixturesModel{},
		datamodel.InvalidModel{},
		datamodel.ValidModel{},
	); err != nil {
		panic(err)
	}
}
