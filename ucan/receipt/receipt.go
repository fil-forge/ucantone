package receipt

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/result"
	rsdm "github.com/fil-forge/ucantone/result/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/invocation"
	rdm "github.com/fil-forge/ucantone/ucan/receipt/datamodel"
	cid "github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
)

const Command = command.Command("/ucan/assert/receipt")

// Receipt is a signed attestation that a task was executed and produced a
// particular result. The result is held as raw CBOR bytes — typed callers
// decode via [Receipt.Out] and UnmarshalCBOR into the schema expected for
// the receipt's task.
type Receipt struct {
	invocation.Invocation
	ran cid.Cid
	out result.Result[[]byte, []byte]
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

// Ran is the CID of the executed task this receipt is for.
func (rcpt *Receipt) Ran() cid.Cid {
	return rcpt.ran
}

func (rcpt *Receipt) MarshalCBOR(w io.Writer) error {
	_, err := w.Write(rcpt.Bytes())
	return err
}

func (rcpt *Receipt) UnmarshalCBOR(r io.Reader) error {
	*rcpt = Receipt{}

	inv := invocation.Invocation{}
	if err := inv.UnmarshalCBOR(r); err != nil {
		return err
	}

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

	rcpt.Invocation = inv
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

	options = append(options, invocation.WithAudience(executor))

	inv, err := invocation.Invoke(executor, executor.DID(), Command, &rdm.ArgsModel{
		Ran: ran,
		Out: outModel,
	}, options...)
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
		Invocation: *inv,
		ran:        ran,
		out:        out,
	}, nil
}

func marshalToRaw(m cbg.CBORMarshaler) (datamodel.Raw, error) {
	var buf bytes.Buffer
	if err := m.MarshalCBOR(&buf); err != nil {
		return datamodel.Raw{}, err
	}
	return datamodel.NewRaw(buf.Bytes()), nil
}
