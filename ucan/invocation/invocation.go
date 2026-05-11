package invocation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	cmd "github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/crypto/signature"
	idm "github.com/fil-forge/ucantone/ucan/invocation/datamodel"
	"github.com/fil-forge/ucantone/ucan/nonce"
	"github.com/fil-forge/ucantone/varsig"
	varsig_dagcbor "github.com/fil-forge/ucantone/varsig/payload/dagcbor"
	cid "github.com/ipfs/go-cid"
	multihash "github.com/multiformats/go-multihash/core"
	cbg "github.com/whyrusleeping/cbor-gen"
)

// Validity is the time an invocation is valid for by default.
const Validity = 30 * time.Second

// UCAN Invocation defines a format for expressing the intention to execute
// delegated UCAN capabilities, and the attested receipts from an execution.
//
// https://github.com/ucan-wg/invocation/blob/main/README.md
type Invocation struct {
	link  cid.Cid
	bytes []byte
	sig   *signature.Signature
	model *idm.EnvelopeModel
	task  *Task
}

// ArgumentsBytes returns the raw CBOR bytes of the args field. Decode directly
// into the typed cborgen struct that corresponds to the invocation's command:
//
//	var args MyArgs
//	err := args.UnmarshalCBOR(bytes.NewReader(inv.ArgumentsBytes()))
//
// https://github.com/ucan-wg/invocation/blob/main/README.md#arguments
func (inv *Invocation) ArgumentsBytes() []byte {
	return inv.model.SigPayload.TokenPayload1_0_0_rc1.Args.Bytes()
}

// The DID of the intended Executor if different from the Subject.
//
// WARNING: May be nil.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#issuer--audience
func (inv *Invocation) Audience() ucan.Principal {
	if inv.model.SigPayload.TokenPayload1_0_0_rc1.Aud == nil {
		return nil
	}
	return inv.model.SigPayload.TokenPayload1_0_0_rc1.Aud
}

// Bytes returns the dag-cbor encoded bytes of this invocation.
func (inv *Invocation) Bytes() []byte {
	return inv.bytes
}

// A provenance claim describing which receipt requested it.
//
// https://github.com/ucan-wg/invocation/blob/main/README.md#cause
func (inv *Invocation) Cause() *cid.Cid {
	return inv.model.SigPayload.TokenPayload1_0_0_rc1.Cause
}

// The command to invoke.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#command
func (inv *Invocation) Command() ucan.Command {
	return inv.model.SigPayload.TokenPayload1_0_0_rc1.Cmd
}

// The timestamp at which the invocation becomes invalid.
//
// https://github.com/ucan-wg/invocation/blob/main/README.md#expiration
func (inv *Invocation) Expiration() *ucan.UTCUnixTimestamp {
	return inv.model.SigPayload.TokenPayload1_0_0_rc1.Exp
}

// An issuance timestamp.
//
// https://github.com/ucan-wg/invocation/blob/main/README.md#issued-at
func (inv *Invocation) IssuedAt() *ucan.UTCUnixTimestamp {
	return inv.model.SigPayload.TokenPayload1_0_0_rc1.Iat
}

// Issuer DID (sender).
//
// https://github.com/ucan-wg/spec/blob/main/README.md#issuer--audience
func (inv *Invocation) Issuer() ucan.Principal {
	return inv.model.SigPayload.TokenPayload1_0_0_rc1.Iss
}

// Link returns the IPLD link that corresponds to the encoded bytes of this
// invocation.
func (inv *Invocation) Link() cid.Cid {
	return inv.link
}

// MetadataBytes returns the raw CBOR bytes of the meta field, or nil if
// metadata is not set.
//
// https://github.com/ucan-wg/invocation/blob/main/README.md#metadata
func (inv *Invocation) MetadataBytes() []byte {
	if inv.model.SigPayload.TokenPayload1_0_0_rc1.Meta == nil {
		return nil
	}
	return inv.model.SigPayload.TokenPayload1_0_0_rc1.Meta.Bytes()
}

// The datamodel this invocation is built from.
func (inv *Invocation) Model() *idm.EnvelopeModel {
	return inv.model
}

// A unique, random nonce. It ensures that multiple (non-idempotent) invocations
// are unique. The nonce SHOULD be empty (0x) for Commands that are idempotent
// (such as deterministic Wasm modules or standards-abiding HTTP PUT requests).
//
// https://github.com/ucan-wg/invocation/blob/main/README.md#nonce
func (inv *Invocation) Nonce() ucan.Nonce {
	return inv.model.SigPayload.TokenPayload1_0_0_rc1.Nonce
}

// The path of authority from the subject to the invoker.
//
// https://github.com/ucan-wg/invocation/blob/main/README.md#proofs
func (inv *Invocation) Proofs() []cid.Cid {
	return inv.model.SigPayload.TokenPayload1_0_0_rc1.Prf
}

// The signature over the payload.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#envelope
func (inv *Invocation) Signature() ucan.Signature {
	return inv.sig
}

// The Subject being invoked.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#subject
func (inv *Invocation) Subject() ucan.Principal {
	return inv.model.SigPayload.TokenPayload1_0_0_rc1.Sub
}

// Task returns the CID of the fields that comprise the task for the invocation.
//
// https://github.com/ucan-wg/invocation/blob/main/README.md#task
func (inv *Invocation) Task() ucan.Task {
	return inv.task
}

func (inv *Invocation) MarshalCBOR(w io.Writer) error {
	_, err := w.Write(inv.Bytes())
	return err
}

func (inv *Invocation) UnmarshalCBOR(r io.Reader) error {
	*inv = Invocation{}
	var w bytes.Buffer
	model := idm.EnvelopeModel{}
	err := model.UnmarshalCBOR(io.TeeReader(r, &w))
	if err != nil {
		return fmt.Errorf("unmarshaling invocation envelope CBOR: %w", err)
	}
	if model.SigPayload.TokenPayload1_0_0_rc1 == nil {
		return errors.New("invalid or unsupported invocation token payload")
	}
	header, err := varsig.Decode(model.SigPayload.Header)
	if err != nil {
		return fmt.Errorf("decoding varsig header: %w", err)
	}
	sig := signature.NewSignature(header, model.Signature)
	task, err := NewTask(
		model.SigPayload.TokenPayload1_0_0_rc1.Sub,
		model.SigPayload.TokenPayload1_0_0_rc1.Cmd,
		model.SigPayload.TokenPayload1_0_0_rc1.Args.Bytes(),
		model.SigPayload.TokenPayload1_0_0_rc1.Nonce,
	)
	if err != nil {
		return fmt.Errorf("creating new task: %w", err)
	}
	root, err := cid.V1Builder{
		Codec:  dagcbor.Code,
		MhType: multihash.SHA2_256,
	}.Sum(w.Bytes())
	if err != nil {
		return fmt.Errorf("hashing invocation bytes: %w", err)
	}
	inv.link = root
	inv.bytes = w.Bytes()
	inv.sig = sig
	inv.model = &model
	inv.task = task
	return nil
}

func (inv *Invocation) MarshalDagJSON(w io.Writer) error {
	return inv.Model().MarshalDagJSON(w)
}

func (inv *Invocation) UnmarshalDagJSON(r io.Reader) error {
	*inv = Invocation{}
	model := idm.EnvelopeModel{}
	err := model.UnmarshalDagJSON(r)
	if err != nil {
		return fmt.Errorf("unmarshaling invocation envelope JSON: %w", err)
	}
	if model.SigPayload.TokenPayload1_0_0_rc1 == nil {
		return errors.New("invalid or unsupported invocation token payload")
	}
	header, err := varsig.Decode(model.SigPayload.Header)
	if err != nil {
		return fmt.Errorf("decoding varsig header: %w", err)
	}
	sig := signature.NewSignature(header, model.Signature)
	task, err := NewTask(
		model.SigPayload.TokenPayload1_0_0_rc1.Sub,
		model.SigPayload.TokenPayload1_0_0_rc1.Cmd,
		model.SigPayload.TokenPayload1_0_0_rc1.Args.Bytes(),
		model.SigPayload.TokenPayload1_0_0_rc1.Nonce,
	)
	if err != nil {
		return fmt.Errorf("creating new task: %w", err)
	}
	// marshal to CBOR so we can calculate canonical CID
	var w bytes.Buffer
	err = model.MarshalCBOR(&w)
	if err != nil {
		return fmt.Errorf("marshaling to CBOR: %w", err)
	}
	root, err := cid.V1Builder{
		Codec:  dagcbor.Code,
		MhType: multihash.SHA2_256,
	}.Sum(w.Bytes())
	if err != nil {
		return fmt.Errorf("hashing invocation bytes: %w", err)
	}
	inv.link = root
	inv.bytes = w.Bytes()
	inv.sig = sig
	inv.model = &model
	inv.task = task
	return nil
}

var _ ucan.Invocation = (*Invocation)(nil)

// Encode invocation to CBOR.
func Encode(inv ucan.Invocation) ([]byte, error) {
	return inv.Bytes(), nil
}

// Decode invocation from CBOR.
func Decode(b []byte) (*Invocation, error) {
	inv := Invocation{}
	err := inv.UnmarshalCBOR(bytes.NewReader(b))
	return &inv, err
}

// Invoke constructs a signed invocation. The args parameter is any
// cborgen-marshalable value whose schema matches what the command's executor
// expects. Pass nil to encode an empty CBOR map.
func Invoke(
	issuer ucan.Signer,
	subject ucan.Subject,
	command ucan.Command,
	args cbg.CBORMarshaler,
	options ...Option,
) (*Invocation, error) {
	cfg := invocationConfig{}
	for _, opt := range options {
		opt(&cfg)
	}

	sigAlgo, ok := varsig.GetSignatureAlgorithmCodec(issuer.SignatureAlgorithm())
	if !ok {
		return nil, fmt.Errorf("missing codec for signature algorithm: %d", issuer.SignatureAlgorithm().Code())
	}
	sigHeader := varsig.NewHeader(sigAlgo, varsig_dagcbor.NewCodec())
	h, err := varsig.Encode(sigHeader)
	if err != nil {
		return nil, fmt.Errorf("encoding varsig header: %w", err)
	}

	cmd, err := cmd.Parse(string(command))
	if err != nil {
		return nil, fmt.Errorf("parsing command: %w", err)
	}

	argsBytes, err := marshalArgs(args)
	if err != nil {
		return nil, fmt.Errorf("marshaling args: %w", err)
	}

	var meta *datamodel.Raw
	if cfg.meta != nil {
		var metaBuf bytes.Buffer
		mp := datamodel.Map(cfg.meta)
		if err := mp.MarshalCBOR(&metaBuf); err != nil {
			return nil, fmt.Errorf("marshaling meta: %w", err)
		}
		r := datamodel.NewRaw(metaBuf.Bytes())
		meta = &r
	}

	nnc := cfg.nnc
	if nnc == nil {
		if cfg.nonnc {
			nnc = []byte{}
		} else {
			nnc = nonce.Generate(16)
		}
	}

	var exp *ucan.UTCUnixTimestamp
	if !cfg.noexp {
		if cfg.exp == nil {
			in30s := ucan.Now() + ucan.UTCUnixTimestamp(Validity.Seconds())
			exp = &in30s
		} else {
			exp = cfg.exp
		}
	}

	iat := cfg.iat
	if iat == nil {
		now := ucan.Now()
		iat = &now
	}

	tokenPayload := &idm.TokenPayloadModel1_0_0_rc1{
		Iss:   issuer.DID(),
		Sub:   subject.DID(),
		Aud:   cfg.aud,
		Cmd:   cmd,
		Args:  datamodel.NewRaw(argsBytes),
		Prf:   cfg.prf,
		Meta:  meta,
		Nonce: nnc,
		Exp:   exp,
		Iat:   iat,
		Cause: cfg.cause,
	}

	sigPayload := idm.SigPayloadModel{
		Header:                h,
		TokenPayload1_0_0_rc1: tokenPayload,
	}

	var sigBuf bytes.Buffer
	err = sigPayload.MarshalCBOR(&sigBuf)
	if err != nil {
		return nil, fmt.Errorf("marshaling signature payload: %w", err)
	}

	sigBytes := issuer.Sign(sigBuf.Bytes())
	sig := signature.NewSignature(sigHeader, sigBytes)

	model := idm.EnvelopeModel{
		Signature:  sigBytes,
		SigPayload: sigPayload,
	}

	task, err := NewTask(
		tokenPayload.Sub,
		tokenPayload.Cmd,
		argsBytes,
		tokenPayload.Nonce,
	)
	if err != nil {
		return nil, fmt.Errorf("creating task: %w", err)
	}

	var envBuf bytes.Buffer
	err = model.MarshalCBOR(&envBuf)
	if err != nil {
		return nil, fmt.Errorf("marshaling invocation CBOR: %w", err)
	}
	root, err := cid.V1Builder{
		Codec:  dagcbor.Code,
		MhType: multihash.SHA2_256,
	}.Sum(envBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("hashing invocation bytes: %w", err)
	}

	return &Invocation{
		link:  root,
		bytes: envBuf.Bytes(),
		sig:   sig,
		model: &model,
		task:  task,
	}, nil
}

// marshalArgs encodes the args via cborgen, falling back to an empty CBOR map
// (0xa0) when args is nil. Returns CBOR bytes suitable for storing in
// [datamodel.Raw].
func marshalArgs(args cbg.CBORMarshaler) ([]byte, error) {
	if args == nil {
		return []byte{0xa0}, nil
	}
	var buf bytes.Buffer
	if err := args.MarshalCBOR(&buf); err != nil {
		return nil, err
	}
	if buf.Len() == 0 {
		return []byte{0xa0}, nil
	}
	return buf.Bytes(), nil
}

func VerifySignature(inv ucan.Invocation, verifier ucan.Verifier) (bool, error) {
	var sub did.DID
	if inv.Subject() != nil {
		sub = inv.Subject().DID()
	}
	var aud *did.DID
	if inv.Audience() != nil {
		a := inv.Audience().DID()
		aud = &a
	}

	var meta *datamodel.Raw
	if mb := inv.MetadataBytes(); len(mb) > 0 {
		r := datamodel.NewRaw(mb)
		meta = &r
	}

	tokenPayload := &idm.TokenPayloadModel1_0_0_rc1{
		Iss:   inv.Issuer().DID(),
		Sub:   sub,
		Aud:   aud,
		Cmd:   inv.Command(),
		Args:  datamodel.NewRaw(inv.ArgumentsBytes()),
		Prf:   inv.Proofs(),
		Meta:  meta,
		Nonce: inv.Nonce(),
		Exp:   inv.Expiration(),
		Iat:   inv.IssuedAt(),
		Cause: inv.Cause(),
	}

	h, err := varsig.Encode(inv.Signature().Header())
	if err != nil {
		return false, fmt.Errorf("encoding varsig header: %w", err)
	}

	sigPayload := idm.SigPayloadModel{
		Header:                h,
		TokenPayload1_0_0_rc1: tokenPayload,
	}

	var sigBuf bytes.Buffer
	err = sigPayload.MarshalCBOR(&sigBuf)
	if err != nil {
		return false, fmt.Errorf("marshaling signature payload: %w", err)
	}

	return inv.Issuer().DID() == verifier.DID() && verifier.Verify(sigBuf.Bytes(), inv.Signature().Bytes()), nil
}
