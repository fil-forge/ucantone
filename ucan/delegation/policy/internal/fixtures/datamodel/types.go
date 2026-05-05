package datamodel

import (
	jsg "github.com/alanshaw/dag-json-gen"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
)

type FixtureModel struct {
	Args     jsg.Deferred    `dagjsongen:"args"`
	Policies []policy.Policy `dagjsongen:"policies"`
}

type FixturesModel struct {
	Valid   []FixtureModel `dagjsongen:"valid"`
	Invalid []FixtureModel `dagjsongen:"invalid"`
}
