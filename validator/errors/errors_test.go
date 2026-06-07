package errors_test

import (
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/invocation"
	verrs "github.com/fil-forge/ucantone/validator/errors"
	"github.com/fil-forge/ucantone/verification"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
)

type token struct {
	ucan.Token
	link cid.Cid
}

func (t token) Link() cid.Cid { return t.link }

func TestNewInvalidSignatureError(t *testing.T) {
	crankWidget := testutil.Must(command.Parse("/widget/crank"))(t)

	issuer := verification.NewIssuer(
		testutil.Must(did.Parse("did:example:123"))(t),
		testutil.RandomSigner(t),
	)
	tok := token{
		link: cid.MustParse("bafkqacyaexampletokenlink"),
		Token: testutil.Must(invocation.Invoke(issuer,
			issuer.DID(),
			crankWidget,
			datamodel.Map{},
		))(t),
	}

	keyID := testutil.Must(did.ParseURL("did:example:123#key-1"))(t)
	controller := testutil.Must(did.Parse("did:example:123"))(t)
	vm := did.VerificationMethod{
		ID:         keyID,
		Controller: controller,
		Type:       did.MultikeyVerificationMethodType,
		Material:   did.GenericMap{did.MultikeyPublicKeyMultibaseProp: "zABC"},
	}

	t.Run("no rejections", func(t *testing.T) {
		err := verrs.NewInvalidSignatureError(tok, nil)
		require.Equal(t,
			`proof "bafkqacyaexampletokenlink" does not have a valid signature from "did:example:123"`+"\n"+
				`  ℹ️ Tried these verification methods:`,
			err.Error())
	})

	t.Run("expired VM", func(t *testing.T) {
		err := verrs.NewInvalidSignatureError(tok, []verrs.VMRejection{
			{VM: vm, Reason: "expired"},
		})
		require.Equal(t,
			`proof "bafkqacyaexampletokenlink" does not have a valid signature from "did:example:123"`+"\n"+
				`  ℹ️ Tried these verification methods:`+"\n"+
				`    - did:example:123#key-1: expired`,
			err.Error())
	})

	t.Run("revoked VM", func(t *testing.T) {
		err := verrs.NewInvalidSignatureError(tok, []verrs.VMRejection{
			{VM: vm, Reason: "revoked"},
		})
		require.Equal(t,
			`proof "bafkqacyaexampletokenlink" does not have a valid signature from "did:example:123"`+"\n"+
				`  ℹ️ Tried these verification methods:`+"\n"+
				`    - did:example:123#key-1: revoked`,
			err.Error())
	})

	t.Run("signature mismatch VM", func(t *testing.T) {
		err := verrs.NewInvalidSignatureError(tok, []verrs.VMRejection{
			{VM: vm, Reason: "signature mismatch"},
		})
		require.Equal(t,
			`proof "bafkqacyaexampletokenlink" does not have a valid signature from "did:example:123"`+"\n"+
				`  ℹ️ Tried these verification methods:`+"\n"+
				`    - did:example:123#key-1: signature mismatch`,
			err.Error())
	})

	t.Run("multiple rejections", func(t *testing.T) {
		vm2ID := testutil.Must(did.ParseURL("did:example:123#key-2"))(t)
		vm2 := did.VerificationMethod{
			ID:         vm2ID,
			Controller: controller,
			Type:       did.MultikeyVerificationMethodType,
			Material:   did.GenericMap{did.MultikeyPublicKeyMultibaseProp: "zDEF"},
		}
		err := verrs.NewInvalidSignatureError(tok, []verrs.VMRejection{
			{VM: vm, Reason: "expired"},
			{VM: vm2, Reason: "signature mismatch"},
		})
		require.Equal(t,
			`proof "bafkqacyaexampletokenlink" does not have a valid signature from "did:example:123"`+"\n"+
				`  ℹ️ Tried these verification methods:`+"\n"+
				`    - did:example:123#key-1: expired`+"\n"+
				`    - did:example:123#key-2: signature mismatch`,
			err.Error())
	})
}
