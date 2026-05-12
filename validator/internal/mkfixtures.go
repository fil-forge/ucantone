package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	ddm "github.com/fil-forge/ucantone/ucan/delegation/datamodel"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	edm "github.com/fil-forge/ucantone/ucan/envelope/datamodel"
	"github.com/fil-forge/ucantone/ucan/invocation"
	idm "github.com/fil-forge/ucantone/ucan/invocation/datamodel"
	verrs "github.com/fil-forge/ucantone/validator/errors"
	fdm "github.com/fil-forge/ucantone/validator/internal/fixtures/datamodel"
	"github.com/fil-forge/ucantone/varsig"
	"github.com/fil-forge/ucantone/varsig/common"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

// Principals are ed25519 private key bytes with varint(0x1300) prefix.
const (
	Alice = "gCa9UfZv+yI5/rvUIt21DaGI7EZJlzFO1uDc5AyJ30c6/w" // did:key:z6MkgGykN9ARNFjEzowVq4mLP2kL4NsyAaDGXeJFQ5qE1bfg
	Bob   = "gCZfj9+RzU2U518TMBNK/fjdGQz34sB4iKE6z+9lQDpCIQ" // did:key:z6MkmT9j6fVZqzXV8u2wVVSu49gYSRYGSQnduWXF6foAJrqz
	Carol = "gCZC43QGw7ZvYQuKTtBwBy+tdjYrKf0hXU3dd+J0HON5dw" // did:key:z6MkmJceVoQSHs45cReEXoLtWm1wosCG8RLxfKwhxoqzoTkC
	Dave  = "gCY4fdpJOoIaIhEpj4HUj9qfgf8BlW7h3T9IbK9pTddRCw" // did:key:z6Mkh7wJtReCeeT9yDR2nR52omKCayS6zbg8tnW8Jok9CJhk
)

var (
	alice = must(ed25519.Decode(must(base64.RawStdEncoding.DecodeString(Alice))))
	bob   = must(ed25519.Decode(must(base64.RawStdEncoding.DecodeString(Bob))))
	carol = must(ed25519.Decode(must(base64.RawStdEncoding.DecodeString(Carol))))
	dave  = must(ed25519.Decode(must(base64.RawStdEncoding.DecodeString(Dave))))
)

var (
	cmd   = must(command.Parse("/msg/send"))
	nonce = [][]byte{
		{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4},
		{5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8},
		{1, 1, 3, 8, 1, 1, 3, 8, 1, 1, 3, 8, 1, 1, 3, 8},
	}
	iat = ucan.UTCUnixTimestamp(must(time.Parse(time.RFC3339, "2025-10-20T00:00:00Z")).Unix())
	vat = ucan.UTCUnixTimestamp(must(time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")).Unix())
)

func main() {
	fixtures := fdm.FixturesModel{
		Version:  "1.0.0-rc.1",
		Comments: "Encoded as dag-json. Time field is the time at which the validation should occur - a Unix timestamp in seconds.",
		Valid: []fdm.ValidModel{
			makeValidSelfSignedFixture(),
			makeValidSingleNonTimeBoundedProofFixture(),
			makeValidSingleActiveProofFixture(),
			makeValidMultipleProofsFixture(),
			makeValidMultipleActiveProofsFixture(),
			makeValidPowerlineFixture(),
			makeValidPolicyMatchFixture(),
		},
		Invalid: []fdm.InvalidModel{
			makeInvalidNoProofFixture(),
			makeInvalidMissingProofFixture(),
			makeInvalidExpiredProofFixture(),
			makeInvalidInactiveProofFixture(),
			makeInvalidProofPrincipalAlignmentFixture(),
			makeInvalidInvocationPrincipalAlignmentFixture(),
			makeInvalidProofSubjectAlignmentFixture(),
			makeInvalidInvocationSubjectAlignmentFixture(),
			makeInvalidExpiredInvocationFixture(),
			makeInvalidProofSignatureFixture(),
			makeInvalidInvocationSignatureFixture(),
			makeInvalidPowerlineFixture(),
			makeInvalidPolicyViolationFixture(),
		},
	}

	var in bytes.Buffer
	must0(fixtures.MarshalDagJSON(&in))
	var out bytes.Buffer
	must0(json.Indent(&out, in.Bytes(), "", "  "))
	fmt.Println(out.String())
}

func makeValidSelfSignedFixture() fdm.ValidModel {
	inv := must(invocation.Invoke(
		alice,
		alice,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithNonce(nonce[0]),
	))

	return fdm.ValidModel{
		Name:        "self signed",
		Description: "no proofs, the subject is the issuer so no proof is necessary",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{},
		Time:        vat,
	}
}

func makeValidSingleNonTimeBoundedProofFixture() fdm.ValidModel {
	dlg0 := must(delegation.Delegate(
		bob,
		alice,
		bob,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	inv := must(invocation.Invoke(
		alice,
		bob,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link()),
		invocation.WithNonce(nonce[1]),
	))

	return fdm.ValidModel{
		Name:        "single non-time bounded proof",
		Description: "a single proof that has no expiry",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0))},
		Time:        vat,
	}
}

func makeValidSingleActiveProofFixture() fdm.ValidModel {
	nbf := ucan.UTCUnixTimestamp(must(time.Parse(time.RFC3339, "2025-10-20T11:08:35Z")).Unix())
	dlg0 := must(delegation.Delegate(
		bob,
		alice,
		bob,
		cmd,
		delegation.WithNotBefore(nbf),
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	inv := must(invocation.Invoke(
		alice,
		bob,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link()),
		invocation.WithNonce(nonce[1]),
	))

	return fdm.ValidModel{
		Name:        "single active non-expired proof",
		Description: "a single proof that has no expiry and is active (a not before timestamp in the past)",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0))},
		Time:        vat,
	}
}

func makeValidMultipleProofsFixture() fdm.ValidModel {
	dlg0 := must(delegation.Delegate(
		carol,
		bob,
		carol,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	dlg1 := must(delegation.Delegate(
		bob,
		alice,
		carol,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[1]),
	))

	inv := must(invocation.Invoke(
		alice,
		carol,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link(), dlg1.Link()),
		invocation.WithNonce(nonce[2]),
	))

	return fdm.ValidModel{
		Name:        "multiple proofs",
		Description: "a proof chain more than one delegation long",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0)), must(delegation.Encode(dlg1))},
		Time:        vat,
	}
}

func makeValidMultipleActiveProofsFixture() fdm.ValidModel {
	dlg0 := must(delegation.Delegate(
		carol,
		bob,
		carol,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	nbf := ucan.UTCUnixTimestamp(must(time.Parse(time.RFC3339, "2025-10-20T11:08:35Z")).Unix())
	dlg1 := must(delegation.Delegate(
		bob,
		alice,
		carol,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNotBefore(nbf),
		delegation.WithNonce(nonce[1]),
	))

	inv := must(invocation.Invoke(
		alice,
		carol,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link(), dlg1.Link()),
		invocation.WithNonce(nonce[2]),
	))

	return fdm.ValidModel{
		Name:        "multiple active proofs",
		Description: "a proof chain more than one delegation long where one or more proofs have a not before time in the past",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0)), must(delegation.Encode(dlg1))},
		Time:        vat,
	}
}

func makeValidPowerlineFixture() fdm.ValidModel {
	dlg0 := must(delegation.Delegate(
		carol,
		bob,
		carol,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	dlg1 := must(delegation.Delegate(
		bob,
		alice,
		nil,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[1]),
	))

	inv := must(invocation.Invoke(
		alice,
		carol,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link(), dlg1.Link()),
		invocation.WithNonce(nonce[2]),
	))

	return fdm.ValidModel{
		Name:        "powerline",
		Description: "a proof chain with a powerline delegation (null value for subject)",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0)), must(delegation.Encode(dlg1))},
		Time:        vat,
	}
}

func makeValidPolicyMatchFixture() fdm.ValidModel {
	dlg0 := must(delegation.Delegate(
		bob,
		alice,
		bob,
		cmd,
		delegation.WithPolicyBuilder(policy.Equal(".answer", 42)),
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	inv := must(invocation.Invoke(
		alice,
		bob,
		cmd,
		datamodel.Map{"answer": 42},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link()),
		invocation.WithNonce(nonce[1]),
	))

	return fdm.ValidModel{
		Name:        "policy match",
		Description: "a policy that matches the invocation arguments",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0))},
		Time:        vat,
	}
}

func makeInvalidNoProofFixture() fdm.InvalidModel {
	inv := must(invocation.Invoke(
		alice,
		carol,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithNonce(nonce[0]),
	))

	return fdm.InvalidModel{
		Name:        "no proof",
		Description: "it has no proofs",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{},
		Error:       fdm.ErrorModel{Name: verrs.InvalidClaimErrorName},
		Time:        vat,
	}
}

func makeInvalidMissingProofFixture() fdm.InvalidModel {
	dlg0 := must(delegation.Delegate(
		bob,
		alice,
		bob,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	inv := must(invocation.Invoke(
		alice,
		carol,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link()),
		invocation.WithNonce(nonce[1]),
	))

	return fdm.InvalidModel{
		Name:        "missing proof",
		Description: "a proof is not provided or resolvable externally",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{},
		Error:       fdm.ErrorModel{Name: verrs.UnavailableProofErrorName},
		Time:        vat,
	}
}

func makeInvalidExpiredProofFixture() fdm.InvalidModel {
	exp := ucan.UTCUnixTimestamp(must(time.Parse(time.RFC3339, "2025-10-20T11:08:35Z")).Unix())
	dlg0 := must(delegation.Delegate(
		bob,
		alice,
		bob,
		cmd,
		delegation.WithExpiration(exp),
		delegation.WithNonce(nonce[0]),
	))

	inv := must(invocation.Invoke(
		alice,
		bob,
		cmd,
		datamodel.Map{},
		invocation.WithAudience(carol),
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link()),
		invocation.WithNonce(nonce[1]),
	))

	return fdm.InvalidModel{
		Name:        "expired proof",
		Description: "a proof is expired",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0))},
		Error:       fdm.ErrorModel{Name: verrs.ExpiredErrorName},
		Time:        vat,
	}
}

func makeInvalidInactiveProofFixture() fdm.InvalidModel {
	nbf := ucan.UTCUnixTimestamp(must(time.Parse(time.RFC3339, "9999-12-31T23:59:59Z")).Unix())
	dlg0 := must(delegation.Delegate(
		bob,
		alice,
		bob,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNotBefore(nbf),
		delegation.WithNonce(nonce[0]),
	))

	inv := must(invocation.Invoke(
		alice,
		bob,
		cmd,
		datamodel.Map{},
		invocation.WithAudience(carol),
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link()),
		invocation.WithNonce(nonce[1]),
	))

	return fdm.InvalidModel{
		Name:        "inactive proof",
		Description: "a proof has a not before time in the future",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0))},
		Error:       fdm.ErrorModel{Name: verrs.TooEarlyErrorName},
		Time:        vat,
	}
}

func makeInvalidProofPrincipalAlignmentFixture() fdm.InvalidModel {
	dlg0 := must(delegation.Delegate(
		dave,
		carol,
		dave,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	dlg1 := must(delegation.Delegate(
		bob,
		alice,
		dave,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[1]),
	))

	inv := must(invocation.Invoke(
		alice,
		dave,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link(), dlg1.Link()),
		invocation.WithNonce(nonce[2]),
	))

	return fdm.InvalidModel{
		Name:        "proof principal alignment",
		Description: "the issuer of a delegation in the proof chain is not the audience of the next delegation",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0)), must(delegation.Encode(dlg1))},
		Error:       fdm.ErrorModel{Name: verrs.PrincipalAlignmentErrorName},
		Time:        vat,
	}
}

func makeInvalidInvocationPrincipalAlignmentFixture() fdm.InvalidModel {
	dlg0 := must(delegation.Delegate(
		dave,
		carol,
		dave,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	dlg1 := must(delegation.Delegate(
		carol,
		bob,
		dave,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[1]),
	))

	inv := must(invocation.Invoke(
		alice,
		dave,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link(), dlg1.Link()),
		invocation.WithNonce(nonce[2]),
	))

	return fdm.InvalidModel{
		Name:        "invocation principal alignment",
		Description: "the audience of the delegation is not the issuer of the invocation",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0)), must(delegation.Encode(dlg1))},
		Error:       fdm.ErrorModel{Name: verrs.PrincipalAlignmentErrorName},
		Time:        vat,
	}
}

func makeInvalidProofSubjectAlignmentFixture() fdm.InvalidModel {
	dlg0 := must(delegation.Delegate(
		carol,
		bob,
		carol,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	dlg1 := must(delegation.Delegate(
		bob,
		alice,
		bob,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[1]),
	))

	inv := must(invocation.Invoke(
		alice,
		carol,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link(), dlg1.Link()),
		invocation.WithNonce(nonce[2]),
	))

	return fdm.InvalidModel{
		Name:        "proof subject alignment",
		Description: "the subject is not the same for every delegation in the proof chain",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0)), must(delegation.Encode(dlg1))},
		Error:       fdm.ErrorModel{Name: verrs.SubjectAlignmentErrorName},
		Time:        vat,
	}
}

func makeInvalidInvocationSubjectAlignmentFixture() fdm.InvalidModel {
	dlg0 := must(delegation.Delegate(
		carol,
		bob,
		carol,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	dlg1 := must(delegation.Delegate(
		bob,
		alice,
		carol,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[1]),
	))

	inv := must(invocation.Invoke(
		alice,
		dave,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link(), dlg1.Link()),
		invocation.WithNonce(nonce[2]),
	))

	return fdm.InvalidModel{
		Name:        "invocation subject alignment",
		Description: "the subject of the invocation is not the same as the subject of the delegation",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0)), must(delegation.Encode(dlg1))},
		Error:       fdm.ErrorModel{Name: verrs.SubjectAlignmentErrorName},
		Time:        vat,
	}
}

func makeInvalidExpiredInvocationFixture() fdm.InvalidModel {
	dlg0 := must(delegation.Delegate(
		bob,
		alice,
		bob,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	exp := ucan.UTCUnixTimestamp(must(time.Parse(time.RFC3339, "2025-10-20T11:08:35Z")).Unix())
	inv := must(invocation.Invoke(
		alice,
		bob,
		cmd,
		datamodel.Map{},
		invocation.WithAudience(carol),
		invocation.WithIssuedAt(iat),
		invocation.WithExpiration(exp),
		invocation.WithProofs(dlg0.Link()),
		invocation.WithNonce(nonce[1]),
	))

	return fdm.InvalidModel{
		Name:        "expired invocation",
		Description: "the invocation is expired",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0))},
		Error:       fdm.ErrorModel{Name: verrs.ExpiredErrorName},
		Time:        vat,
	}
}

func makeInvalidProofSignatureFixture() fdm.InvalidModel {
	h := must(varsig.Encode(common.Ed25519DagCbor))

	tokenPayload := &ddm.TokenPayloadModel1_0_0_rc1{
		Iss:   bob.DID(),
		Aud:   alice.DID(),
		Sub:   bob.DID(),
		Cmd:   cmd,
		Pol:   policy.Policy{},
		Nonce: nonce[0],
	}

	sigPayload := ddm.SigPayloadModel{
		Header:                h,
		TokenPayload1_0_0_rc1: tokenPayload,
	}

	var spBuf bytes.Buffer
	must0(sigPayload.MarshalCBOR(&spBuf))

	envelope := edm.EnvelopeModel{
		Signature:  []byte{1, 2, 3},
		SigPayload: datamodel.NewRaw(spBuf.Bytes()),
	}

	var dlg0Buf bytes.Buffer
	must0(envelope.MarshalCBOR(&dlg0Buf))
	dlg0Link := must(cid.V1Builder{
		Codec:  dagcbor.Code,
		MhType: multihash.SHA2_256,
	}.Sum(dlg0Buf.Bytes()))

	inv := must(invocation.Invoke(
		alice,
		bob,
		cmd,
		datamodel.Map{},
		invocation.WithAudience(carol),
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0Link),
		invocation.WithNonce(nonce[1]),
	))

	return fdm.InvalidModel{
		Name:        "invalid proof signature",
		Description: "the signature of a proof is not verifiable",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{dlg0Buf.Bytes()},
		Error:       fdm.ErrorModel{Name: verrs.InvalidSignatureErrorName},
		Time:        vat,
	}
}

func makeInvalidInvocationSignatureFixture() fdm.InvalidModel {
	h := must(varsig.Encode(common.Ed25519DagCbor))

	tokenPayload := &idm.TokenPayloadModel1_0_0_rc1{
		Iss:   alice.DID(),
		Sub:   carol.DID(),
		Cmd:   cmd,
		Args:  datamodel.NewRaw([]byte{0xa0}),
		Nonce: nonce[0],
		Iat:   &iat,
	}

	sigPayload := idm.SigPayloadModel{
		Header:                h,
		TokenPayload1_0_0_rc1: tokenPayload,
	}

	var spBuf bytes.Buffer
	must0(sigPayload.MarshalCBOR(&spBuf))

	envelope := edm.EnvelopeModel{
		Signature:  []byte{1, 2, 3},
		SigPayload: datamodel.NewRaw(spBuf.Bytes()),
	}

	var envBuf bytes.Buffer
	must0(envelope.MarshalCBOR(&envBuf))

	return fdm.InvalidModel{
		Name:        "invalid invocation signature",
		Description: "the signature of the invocation is not verifiable",
		Invocation:  envBuf.Bytes(),
		Proofs:      [][]byte{},
		Error:       fdm.ErrorModel{Name: verrs.InvalidSignatureErrorName},
		Time:        vat,
	}
}

func makeInvalidPowerlineFixture() fdm.InvalidModel {
	dlg0 := must(delegation.Delegate(
		bob,
		alice,
		nil,
		cmd,
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	inv := must(invocation.Invoke(
		alice,
		carol,
		cmd,
		datamodel.Map{},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link()),
		invocation.WithNonce(nonce[1]),
	))

	return fdm.InvalidModel{
		Name:        "invalid powerline",
		Description: "the root delegation has a null subject",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0))},
		Error:       fdm.ErrorModel{Name: verrs.InvalidClaimErrorName},
		Time:        vat,
	}
}

func makeInvalidPolicyViolationFixture() fdm.InvalidModel {
	dlg0 := must(delegation.Delegate(
		bob,
		alice,
		bob,
		cmd,
		delegation.WithPolicyBuilder(policy.Equal(".answer", 42)),
		delegation.WithNoExpiration(),
		delegation.WithNonce(nonce[0]),
	))

	inv := must(invocation.Invoke(
		alice,
		bob,
		cmd,
		datamodel.Map{"answer": 41},
		invocation.WithIssuedAt(iat),
		invocation.WithNoExpiration(),
		invocation.WithProofs(dlg0.Link()),
		invocation.WithNonce(nonce[1]),
	))

	return fdm.InvalidModel{
		Name:        "policy violation",
		Description: "the invocation violates a policy set in an delegation",
		Invocation:  must(invocation.Encode(inv)),
		Proofs:      [][]byte{must(delegation.Encode(dlg0))},
		Error:       fdm.ErrorModel{Name: policy.MatchErrorName},
		Time:        vat,
	}
}

func must[O any](o O, x error) O {
	if x != nil {
		panic(x)
	}
	return o
}

func must0(x error) {
	if x != nil {
		panic(x)
	}
}
