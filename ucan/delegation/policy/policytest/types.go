// Package policytest holds argument-struct fixtures (and their generated policy
// field descriptors) used by the policy package's external tests. The types
// mirror real libforge command arguments and the cborgen tags that drive the
// on-the-wire map keys, so selector-path derivation is exercised exactly as it
// would be in production.
package policytest

import (
	"math/big"

	"github.com/multiformats/go-multihash"
)

// Blob mirrors github.com/fil-forge/libforge/commands/blob.Blob.
type Blob struct {
	Digest multihash.Multihash `cborgen:"digest"`
	Size   uint64              `cborgen:"size"`
}

// RetrieveArgs mirrors blob.RetrieveArguments (a nested struct field).
type RetrieveArgs struct {
	Blob Blob `cborgen:"blob"`
}

// Shard is a slice element used to exercise the Each/Some quantifiers.
type Shard struct {
	Codec uint64 `cborgen:"codec"`
}

// Manifest exercises a scalar field plus a slice-of-struct field.
type Manifest struct {
	Name   string  `cborgen:"name"`
	Shards []Shard `cborgen:"shards"`
}

// SignArgs mirrors libforge pdp/sign args, whose ID fields are *big.Int
// (CBOR bignums) — a struct-with-no-exported-fields leaf.
type SignArgs struct {
	DataSet *big.Int `cborgen:"dataSet"`
}

// Envelope exercises an optional (pointer) navigable struct field: *Blob is
// dereferenced to the Blob descriptor and occupies the same selector position.
type Envelope struct {
	Primary  Blob  `cborgen:"primary"`
	Fallback *Blob `cborgen:"fallback,omitempty"`
}

// Tagged exercises a slice of scalars, whose element descriptor is an identity
// selector (".") quantified over by Each/Some.
type Tagged struct {
	Tags []string `cborgen:"tags"`
}

// Labels exercises a string-keyed map field; EachMap/SomeMap quantify over the
// map's values.
type Labels struct {
	Meta map[string]string `cborgen:"meta"`
}

// Bundle exercises a slice whose element struct itself contains nested structs,
// so the element descriptor's selector paths must be element-relative
// (".primary.digest"), not rooted at the slice (".items.primary.digest").
type Bundle struct {
	Items []Envelope `cborgen:"items"`
}
