package datamodel

import (
	"github.com/fil-forge/ucantone/did"
	"github.com/ipfs/go-cid"
)

type TestObject struct {
	Bytes []byte `cborgen:"bytes"`
}

type TestObject2 struct {
	Str   string `cborgen:"str"`
	Bytes []byte `cborgen:"bytes"`
}

type TestArgs struct {
	ID    did.DID     `cborgen:"id"`
	Link  cid.Cid     `cborgen:"link"`
	Str   string      `cborgen:"str"`
	Num   int64       `cborgen:"num"`
	Bytes []byte      `cborgen:"bytes"`
	Obj   TestObject  `cborgen:"obj"`
	Obj2  TestObject2 `cborgen:"obj2"`
	List  []string    `cborgen:"list"`
}
