package datamodel

import (
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

const Tag = "ucan/inv@1.0.0-rc.1"

type TaskModel struct {
	Sub   did.DID       `cborgen:"sub" dagjsongen:"sub"`
	Cmd   ucan.Command  `cborgen:"cmd" dagjsongen:"cmd"`
	Args  datamodel.Raw `cborgen:"args" dagjsongen:"args"`
	Nonce []byte    `cborgen:"nonce" dagjsongen:"nonce"`
}

type TokenPayloadModel1_0_0_rc1 struct {
	// Issuer DID (sender).
	Iss did.DID `cborgen:"iss" dagjsongen:"iss"`
	// The Subject being invoked.
	Sub did.DID `cborgen:"sub" dagjsongen:"sub"`
	// The DID of the intended Executor if different from the Subject.
	Aud *did.DID `cborgen:"aud,omitempty" dagjsongen:"aud,omitempty"`
	// The command to invoke.
	Cmd ucan.Command `cborgen:"cmd" dagjsongen:"cmd"`
	// The command arguments.
	Args datamodel.Raw `cborgen:"args" dagjsongen:"args"`
	// Delegations that prove the chain of authority.
	Prf []cid.Cid `cborgen:"prf" dagjsongen:"prf"`
	// Arbitrary metadata.
	Meta *datamodel.Raw `cborgen:"meta,omitempty" dagjsongen:"meta,omitempty"`
	// A unique, random nonce.
	Nonce []byte `cborgen:"nonce" dagjsongen:"nonce"`
	// The timestamp at which the invocation becomes invalid.
	Exp *ucan.UTCUnixTimestamp `cborgen:"exp" dagjsongen:"exp"`
	// The timestamp at which the invocation was created.
	Iat *ucan.UTCUnixTimestamp `cborgen:"iat,omitempty" dagjsongen:"iat,omitempty"`
	// CID of the receipt that enqueued the Task.
	Cause *cid.Cid `cborgen:"cause,omitempty" dagjsongen:"cause,omitempty"`
}

type SigPayloadModel struct {
	// The Varsig v1 header.
	Header []byte `cborgen:"h" dagjsongen:"h"`
	// The UCAN token payload.
	TokenPayload1_0_0_rc1 *TokenPayloadModel1_0_0_rc1 `cborgen:"ucan/inv@1.0.0-rc.1,omitempty" dagjsongen:"ucan/inv@1.0.0-rc.1,omitempty"`
}
