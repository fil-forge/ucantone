package datamodel

import "github.com/ipfs/go-cid"

type AwaitAnyModel struct {
	AwaitAny cid.Cid `cborgen:"await/*" dagjsongen:"await/*"`
}

type AwaitOKModel struct {
	AwaitOK cid.Cid `cborgen:"await/ok" dagjsongen:"await/ok"`
}

type AwaitErrorModel struct {
	AwaitError cid.Cid `cborgen:"await/error" dagjsongen:"await/error"`
}
