package receipt

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	cid "github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/result"
	rsdm "github.com/fil-forge/ucantone/result/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/invocation"
	rdm "github.com/fil-forge/ucantone/ucan/receipt/datamodel"
)

const Command = command.Command("/ucan/assert/receipt")

// Receipt is a signed attestation that a task was executed and produced a
// particular result.
//
// On the wire a receipt is a /ucan/assert/receipt invocation (per the UCAN WG
// draft, ucan-wg/receipt#1): the executor is issuer/subject/audience and the
// Ran/Out fields travel in the invocation's args. That wire shape is
// deliberate and is not changed here.
//
// At the Go level, Receipt wraps the underlying invocation as an unexported
// field rather than embedding it, so a *Receipt does not satisfy
// ucan.Invocation and only exposes accessors that are meaningful for a
// receipt. The result is held as raw CBOR bytes — typed callers decode via
// [Receipt.Out] into the schema expected for the receipt's task.
type Receipt struct {
	inv invocation.Invocation
	ran cid.Cid
	out result.Result[[]byte, []byte]
}

// Issuer is the DID of the executor that signed this attestation.
func (rcpt *Receipt) Issuer() did.DID {
	return rcpt.inv.Issuer()
}

// Ran is the CID of the executed task this receipt is for.
func (rcpt *Receipt) Ran() cid.Cid {
	return rcpt.ran
}

// Out is the attested result of the execution of the task. The Result's
// Ok and Err branches hold raw CBOR bytes; decode into the typed cborgen
// struct that matches the executed task's expected output:
//
//	if out := rcpt.Out(); out.IsOK() {
//	    okBytes, _ := out.Unpack()
//	    var v MyResult
//	    v.UnmarshalCBOR(bytes.NewReader(okBytes))
//	    // ...
//	} else {
//	    _, errBytes := out.Unpack()
//	    // ...
//	}
func (rcpt *Receipt) Out() result.Result[[]byte, []byte] {
	return rcpt.out
}

// IssuedAt is the timestamp at which the executor signed this receipt, or nil
// if unset.
func (rcpt *Receipt) IssuedAt() *ucan.UnixTimestamp {
	return rcpt.inv.IssuedAt()
}

// Nonce returns the receipt's nonce.
func (rcpt *Receipt) Nonce() []byte {
	return rcpt.inv.Nonce()
}

// MetadataBytes returns the raw CBOR bytes of the meta field, or nil if
// metadata is not set.
func (rcpt *Receipt) MetadataBytes() []byte {
	return rcpt.inv.MetadataBytes()
}

// SignedBytes returns the raw CBOR bytes of the SigPayload — the bytes the
// issuer signed over. Verification operates on these directly.
func (rcpt *Receipt) SignedBytes() []byte {
	return rcpt.inv.SignedBytes()
}

// Signature returns the executor's signature over the SignedBytes.
func (rcpt *Receipt) Signature() ucan.Signature {
	return rcpt.inv.Signature()
}

// Link returns the IPLD link that corresponds to the encoded bytes.
func (rcpt *Receipt) Link() cid.Cid {
	return rcpt.inv.Link()
}

// Bytes returns the dag-cbor encoded bytes of this receipt.
func (rcpt *Receipt) Bytes() []byte {
	return rcpt.inv.Bytes()
}

func (rcpt *Receipt) MarshalCBOR(w io.Writer) error {
	return rcpt.inv.MarshalCBOR(w)
}

func (rcpt *Receipt) UnmarshalCBOR(r io.Reader) error {
	inv := invocation.Invocation{}
	if err := inv.UnmarshalCBOR(r); err != nil {
		return err
	}
	return rcpt.fromInvocation(inv)
}

func (rcpt *Receipt) MarshalDagJSON(w io.Writer) error {
	return rcpt.inv.MarshalDagJSON(w)
}

func (rcpt *Receipt) UnmarshalDagJSON(r io.Reader) error {
	inv := invocation.Invocation{}
	if err := inv.UnmarshalDagJSON(r); err != nil {
		return err
	}
	return rcpt.fromInvocation(inv)
}

// fromInvocation validates that inv is a well-formed receipt invocation and
// populates rcpt from it.
func (rcpt *Receipt) fromInvocation(inv invocation.Invocation) error {
	*rcpt = Receipt{}

	if inv.Command() != Command {
		return fmt.Errorf("invalid receipt command %s, expected %s", inv.Command().String(), Command.String())
	}

	var receiptArgs rdm.ArgsModel
	if err := receiptArgs.UnmarshalCBOR(bytes.NewReader(inv.ArgumentsBytes())); err != nil {
		return fmt.Errorf("decoding receipt arguments: %w", err)
	}

	var out result.Result[[]byte, []byte]
	switch {
	case receiptArgs.Out.Ok != nil:
		out = result.OK[[]byte, []byte](receiptArgs.Out.Ok.Bytes())
	case receiptArgs.Out.Err != nil:
		out = result.Err[[]byte, []byte](receiptArgs.Out.Err.Bytes())
	default:
		return errors.New("invalid result, neither ok nor error")
	}

	rcpt.inv = inv
	rcpt.ran = receiptArgs.Ran
	rcpt.out = out
	return nil
}

var _ ucan.Receipt = (*Receipt)(nil)

// Encode receipt to CBOR.
func Encode(rcpt ucan.Receipt) ([]byte, error) {
	return rcpt.Bytes(), nil
}

// Decode receipt from CBOR.
func Decode(b []byte) (*Receipt, error) {
	rcpt := Receipt{}
	err := rcpt.UnmarshalCBOR(bytes.NewReader(b))
	return &rcpt, err
}

// IssueOK creates a receipt attesting to a successful execution. The ok value
// is any cborgen-marshalable type whose schema matches what the executed
// task's command expects to produce.
func IssueOK(executor ucan.Signer, ran cid.Cid, ok cbg.CBORMarshaler, options ...Option) (*Receipt, error) {
	return issue(executor, ran, ok, nil, options...)
}

// IssueErr creates a receipt attesting to a failed execution. The err value
// is any cborgen-marshalable type representing the failure.
func IssueErr(executor ucan.Signer, ran cid.Cid, err cbg.CBORMarshaler, options ...Option) (*Receipt, error) {
	return issue(executor, ran, nil, err, options...)
}

func issue(executor ucan.Signer, ran cid.Cid, ok, errVal cbg.CBORMarshaler, options ...Option) (*Receipt, error) {
	if (ok == nil) == (errVal == nil) {
		return nil, errors.New("issue requires exactly one of ok or err to be non-nil")
	}

	cfg := receiptConfig{}
	for _, opt := range options {
		opt(&cfg)
	}

	var outModel rsdm.ResultModel
	var outBytes []byte
	if ok != nil {
		raw, err := marshalToRaw(ok)
		if err != nil {
			return nil, fmt.Errorf("marshaling ok: %w", err)
		}
		outModel.Ok = &raw
		outBytes = raw.Bytes()
	} else {
		raw, err := marshalToRaw(errVal)
		if err != nil {
			return nil, fmt.Errorf("marshaling err: %w", err)
		}
		outModel.Err = &raw
		outBytes = raw.Bytes()
	}

	invOpts := append(cfg.invOpts, invocation.WithAudience(executor.DID()))

	inv, err := invocation.Invoke(executor, executor.DID(), Command, &rdm.ArgsModel{
		Ran: ran,
		Out: outModel,
	}, invOpts...)
	if err != nil {
		return nil, err
	}

	var out result.Result[[]byte, []byte]
	if ok != nil {
		out = result.OK[[]byte, []byte](outBytes)
	} else {
		out = result.Err[[]byte, []byte](outBytes)
	}

	return &Receipt{
		inv: *inv,
		ran: ran,
		out: out,
	}, nil
}

// VerifySignature verifies the receipt's signature against the literal
// signed-payload bytes preserved on decode.
func VerifySignature(rcpt ucan.Receipt, verifier ucan.Verifier) (bool, error) {
	if rcpt.Issuer() != verifier.DID() {
		return false, nil
	}
	return verifier.Verify(rcpt.SignedBytes(), rcpt.Signature().Bytes()), nil
}

func marshalToRaw(m cbg.CBORMarshaler) (datamodel.Raw, error) {
	var buf bytes.Buffer
	if err := m.MarshalCBOR(&buf); err != nil {
		return datamodel.Raw{}, err
	}
	return datamodel.NewRaw(buf.Bytes()), nil
}
