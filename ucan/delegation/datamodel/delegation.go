package datamodel

import (
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	edm "github.com/fil-forge/ucantone/ucan/envelope/datamodel"
)

const Tag = "ucan/dlg@1.0.0-rc.1"

type TokenPayloadModel1_0_0_rc1 struct {
	// Issuer DID (sender).
	Iss did.DID `cborgen:"iss" dagjsongen:"iss"`
	// The DID of the intended Executor if different from the Subject.
	Aud did.DID `cborgen:"aud" dagjsongen:"aud"`
	// The principal the chain is about.
	Sub did.DID `cborgen:"sub" dagjsongen:"sub"`
	// The command to eventually invoke.
	Cmd ucan.Command `cborgen:"cmd" dagjsongen:"cmd"`
	// Additional constraints on eventual invocation arguments, expressed in the
	// UCAN Policy Language.
	Pol policy.Policy `cborgen:"pol" dagjsongen:"pol"`
	// A unique, random nonce.
	Nonce ucan.Nonce `cborgen:"nonce" dagjsongen:"nonce"`
	// Arbitrary metadata.
	Meta *datamodel.Raw `cborgen:"meta,omitempty" dagjsongen:"meta,omitempty"`
	// "Not before" UTC Unix Timestamp in seconds (valid from).
	Nbf *ucan.UTCUnixTimestamp `cborgen:"nbf,omitempty" dagjsongen:"nbf,omitempty"`
	// Expiration UTC Unix Timestamp in seconds (valid until).
	Exp *ucan.UTCUnixTimestamp `cborgen:"exp" dagjsongen:"exp"`
}

type SigPayloadModel struct {
	// The Varsig v1 header.
	Header []byte `cborgen:"h" dagjsongen:"h"`
	// The UCAN token payload.
	TokenPayload1_0_0_rc1 *TokenPayloadModel1_0_0_rc1 `cborgen:"ucan/dlg@1.0.0-rc.1,omitempty" dagjsongen:"ucan/dlg@1.0.0-rc.1,omitempty"`
}

type EnvelopeModel edm.EnvelopeModel[SigPayloadModel]
