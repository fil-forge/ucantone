package delegation

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/ipfs/go-cid"
	multihash "github.com/multiformats/go-multihash/core"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	cmd "github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/crypto/signature"
	ddm "github.com/fil-forge/ucantone/ucan/delegation/datamodel"
	edm "github.com/fil-forge/ucantone/ucan/envelope/datamodel"
	"github.com/fil-forge/ucantone/ucan/nonce"
	"github.com/fil-forge/ucantone/varsig"
	varsig_dagcbor "github.com/fil-forge/ucantone/varsig/payload/dagcbor"
)

type Delegation struct {
	link       cid.Cid
	bytes      []byte
	sig        *signature.Signature
	envelope   *edm.EnvelopeModel
	sigPayload *ddm.SigPayloadModel
}

// Audience can be conceptualized as the receiver of a postal letter.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#issuer--audience
func (d *Delegation) Audience() ucan.Principal {
	return d.sigPayload.TokenPayload1_0_0_rc1.Aud
}

// Bytes returns the dag-cbor encoded bytes of this delegation.
func (d *Delegation) Bytes() []byte {
	return d.bytes
}

// Command is a / delimited path describing the set of commands delegated.
//
// https://github.com/ucan-wg/delegation/blob/main/README.md#command
func (d *Delegation) Command() ucan.Command {
	return d.sigPayload.TokenPayload1_0_0_rc1.Cmd
}

// Expiration is the time at which the delegation becomes invalid.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#time-bounds
func (d *Delegation) Expiration() *ucan.UTCUnixTimestamp {
	return d.sigPayload.TokenPayload1_0_0_rc1.Exp
}

// Issuer can be conceptualized as the sender of a postal letter.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#issuer--audience
func (d *Delegation) Issuer() ucan.Principal {
	return d.sigPayload.TokenPayload1_0_0_rc1.Iss
}

// Link returns the IPLD link that corresponds to the encoded bytes of this
// delegation.
func (d *Delegation) Link() cid.Cid {
	return d.link
}

// MetadataBytes returns the raw CBOR bytes of the meta field, or nil if
// metadata is not set.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#metadata
func (d *Delegation) MetadataBytes() []byte {
	if d.sigPayload.TokenPayload1_0_0_rc1.Meta == nil {
		return nil
	}
	return d.sigPayload.TokenPayload1_0_0_rc1.Meta.Bytes()
}

// Envelope returns the raw envelope (signature + signed-payload bytes).
func (d *Delegation) Envelope() *edm.EnvelopeModel {
	return d.envelope
}

// SigPayload returns the decoded signature payload (varsig header + token payload).
func (d *Delegation) SigPayload() *ddm.SigPayloadModel {
	return d.sigPayload
}

// SignedBytes returns the raw CBOR bytes of the SigPayload — the bytes the
// issuer signed over.
func (d *Delegation) SignedBytes() []byte {
	return d.envelope.SigPayload.Bytes()
}

// Nonce helps prevent replay attacks and ensures a unique CID per delegation.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#nonce
func (d *Delegation) Nonce() ucan.Nonce {
	return d.sigPayload.TokenPayload1_0_0_rc1.Nonce
}

// NotBefore delays the ability to invoke a UCAN.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#time-bounds
func (d *Delegation) NotBefore() *ucan.UTCUnixTimestamp {
	return d.sigPayload.TokenPayload1_0_0_rc1.Nbf
}

// Additional constraints on eventual invocation arguments, expressed in the
// UCAN Policy Language.
//
// https://github.com/ucan-wg/delegation/blob/main/README.md#policy
func (d *Delegation) Policy() ucan.Policy {
	return d.sigPayload.TokenPayload1_0_0_rc1.Pol
}

// The signature over the payload.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#envelope
func (d *Delegation) Signature() ucan.Signature {
	return d.sig
}

// The Subject that will eventually be invoked.
//
// https://github.com/ucan-wg/delegation/blob/main/README.md#subject
func (d *Delegation) Subject() ucan.Principal {
	sub := d.sigPayload.TokenPayload1_0_0_rc1.Sub
	if sub == (did.DID{}) {
		return nil
	}
	return sub
}

func (d *Delegation) MarshalCBOR(w io.Writer) error {
	_, err := w.Write(d.Bytes())
	return err
}

func (d *Delegation) UnmarshalCBOR(r io.Reader) error {
	*d = Delegation{}
	var w bytes.Buffer
	envelope := edm.EnvelopeModel{}
	if err := envelope.UnmarshalCBOR(io.TeeReader(r, &w)); err != nil {
		return fmt.Errorf("unmarshaling delegation envelope CBOR: %w", err)
	}
	sigPayload := ddm.SigPayloadModel{}
	if err := sigPayload.UnmarshalCBOR(bytes.NewReader(envelope.SigPayload.Bytes())); err != nil {
		return fmt.Errorf("unmarshaling delegation signed payload: %w", err)
	}
	if sigPayload.TokenPayload1_0_0_rc1 == nil {
		return errors.New("invalid or unsupported delegation token payload")
	}
	header, err := varsig.Decode(sigPayload.Header)
	if err != nil {
		return fmt.Errorf("decoding varsig header: %w", err)
	}
	sig := signature.NewSignature(header, envelope.Signature)
	root, err := cid.V1Builder{
		Codec:  dagcbor.Code,
		MhType: multihash.SHA2_256,
	}.Sum(w.Bytes())
	if err != nil {
		return fmt.Errorf("hashing delegation bytes: %w", err)
	}
	d.link = root
	d.bytes = w.Bytes()
	d.sig = sig
	d.envelope = &envelope
	d.sigPayload = &sigPayload
	return nil
}

func (d *Delegation) MarshalDagJSON(w io.Writer) error {
	return d.envelope.MarshalDagJSON(w)
}

func (d *Delegation) UnmarshalDagJSON(r io.Reader) error {
	*d = Delegation{}
	envelope := edm.EnvelopeModel{}
	if err := envelope.UnmarshalDagJSON(r); err != nil {
		return fmt.Errorf("unmarshaling delegation envelope JSON: %w", err)
	}
	sigPayload := ddm.SigPayloadModel{}
	if err := sigPayload.UnmarshalCBOR(bytes.NewReader(envelope.SigPayload.Bytes())); err != nil {
		return fmt.Errorf("unmarshaling delegation signed payload: %w", err)
	}
	if sigPayload.TokenPayload1_0_0_rc1 == nil {
		return errors.New("invalid or unsupported delegation token payload")
	}
	header, err := varsig.Decode(sigPayload.Header)
	if err != nil {
		return fmt.Errorf("decoding varsig header: %w", err)
	}
	sig := signature.NewSignature(header, envelope.Signature)
	// marshal to CBOR so we can calculate canonical CID
	var envBuf bytes.Buffer
	if err := envelope.MarshalCBOR(&envBuf); err != nil {
		return fmt.Errorf("marshaling to CBOR: %w", err)
	}
	root, err := cid.V1Builder{
		Codec:  dagcbor.Code,
		MhType: multihash.SHA2_256,
	}.Sum(envBuf.Bytes())
	if err != nil {
		return fmt.Errorf("hashing delegation bytes: %w", err)
	}
	d.link = root
	d.bytes = envBuf.Bytes()
	d.sig = sig
	d.envelope = &envelope
	d.sigPayload = &sigPayload
	return nil
}

var _ ucan.Delegation = (*Delegation)(nil)

// Encode delegation to CBOR.
func Encode(dlg ucan.Delegation) ([]byte, error) {
	return dlg.Bytes(), nil
}

// Decode delegation from CBOR.
func Decode(b []byte) (*Delegation, error) {
	d := Delegation{}
	err := d.UnmarshalCBOR(bytes.NewReader(b))
	return &d, err
}

func Delegate(
	issuer ucan.Signer,
	audience ucan.Principal,
	subject ucan.Subject,
	command ucan.Command,
	options ...Option,
) (*Delegation, error) {
	cfg := delegationConfig{}
	for _, opt := range options {
		err := opt(&cfg)
		if err != nil {
			return nil, err
		}
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

	var sub did.DID
	if subject != nil {
		sub = subject.DID()
	}

	cmd, err := cmd.Parse(string(command))
	if err != nil {
		return nil, fmt.Errorf("parsing command: %w", err)
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
			in30s := ucan.Now() + 30
			exp = &in30s
		} else {
			exp = cfg.exp
		}
	}

	tokenPayload := &ddm.TokenPayloadModel1_0_0_rc1{
		Iss:   issuer.DID(),
		Aud:   audience.DID(),
		Sub:   sub,
		Cmd:   cmd,
		Pol:   cfg.pol,
		Nonce: nnc,
		Meta:  meta,
		Nbf:   cfg.nbf,
		Exp:   exp,
	}

	sigPayload := ddm.SigPayloadModel{
		Header:                h,
		TokenPayload1_0_0_rc1: tokenPayload,
	}

	var sigBuf bytes.Buffer
	if err := sigPayload.MarshalCBOR(&sigBuf); err != nil {
		return nil, fmt.Errorf("marshaling token payload: %w", err)
	}

	sigBytes := issuer.Sign(sigBuf.Bytes())
	sig := signature.NewSignature(sigHeader, sigBytes)

	envelope := edm.EnvelopeModel{
		Signature:  sigBytes,
		SigPayload: datamodel.NewRaw(sigBuf.Bytes()),
	}

	var envBuf bytes.Buffer
	if err := envelope.MarshalCBOR(&envBuf); err != nil {
		return nil, fmt.Errorf("marshaling delegation CBOR: %w", err)
	}
	root, err := cid.V1Builder{
		Codec:  dagcbor.Code,
		MhType: multihash.SHA2_256,
	}.Sum(envBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("hashing delegation bytes: %w", err)
	}

	return &Delegation{
		link:       root,
		bytes:      envBuf.Bytes(),
		sig:        sig,
		envelope:   &envelope,
		sigPayload: &sigPayload,
	}, nil
}

// VerifySignature verifies the delegation's signature against the literal
// signed-payload bytes preserved on decode. No reconstruction of the signing
// payload from typed fields — verification operates on the exact bytes the
// issuer signed, per the UCAN spec.
func VerifySignature(dlg ucan.Delegation, verifier ucan.Verifier) (bool, error) {
	if dlg.Issuer().DID() != verifier.DID() {
		return false, nil
	}
	return verifier.Verify(dlg.SignedBytes(), dlg.Signature().Bytes()), nil
}
