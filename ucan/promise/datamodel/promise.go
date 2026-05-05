package datamodel

import "github.com/fil-forge/ucantone/ucan"

type AwaitAnyModel struct {
	AwaitAny ucan.Link `cborgen:"await/*" dagjsongen:"await/*"`
}

type AwaitOKModel struct {
	AwaitOK ucan.Link `cborgen:"await/ok" dagjsongen:"await/ok"`
}

type AwaitErrorModel struct {
	AwaitError ucan.Link `cborgen:"await/error" dagjsongen:"await/error"`
}
