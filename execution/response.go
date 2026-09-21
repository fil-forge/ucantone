package execution

import (
	"fmt"

	"github.com/fil-forge/ucantone/errors"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/receipt"
	"github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
)

type ExecResponse struct {
	issuer            ucan.Issuer
	task              cid.Cid
	receipt           ucan.Receipt
	metadata          ucan.Container
	receiptTimestamp  bool
	receiptExpiration *ucan.UnixTimestamp
}

type ResponseOption func(r *ExecResponse) error

func WithIssuer(issuer ucan.Issuer) ResponseOption {
	return func(resp *ExecResponse) error {
		resp.issuer = issuer
		return nil
	}
}

func WithReceipt(receipt ucan.Receipt) ResponseOption {
	return func(resp *ExecResponse) error {
		resp.SetReceipt(receipt)
		return nil
	}
}

// WithReceiptTimestamp configures the response to issue receipts with
// issuance timestamps. Note: this option should be ordered before [WithSuccess]
// or [WithFailure], since these options issue a receipt.
func WithReceiptTimestamp(enabled bool) ResponseOption {
	return func(resp *ExecResponse) error {
		resp.receiptTimestamp = enabled
		return nil
	}
}

// WithReceiptExpiration configures the response to issue receipts with the
// given expiration. Note: this option should be ordered before [WithSuccess]
// or [WithFailure], since these options issue a receipt.
func WithReceiptExpiration(exp ucan.UnixTimestamp) ResponseOption {
	return func(resp *ExecResponse) error {
		resp.receiptExpiration = &exp
		return nil
	}
}

// WithSuccess issues and sets a receipt for a successful execution of a task.
func WithSuccess(o cbg.CBORMarshaler) ResponseOption {
	return func(resp *ExecResponse) error {
		return resp.SetSuccess(o)
	}
}

// WithFailure issues and sets a receipt for a failed execution of a task.
func WithFailure(x error) ResponseOption {
	return func(resp *ExecResponse) error {
		return resp.SetFailure(x)
	}
}

func WithMetadata(m ucan.Container) ResponseOption {
	return func(resp *ExecResponse) error {
		resp.SetMetadata(m)
		return nil
	}
}

// NewResponse creates a new response object, representing the result of
// executing a task.
func NewResponse(task cid.Cid, options ...ResponseOption) (*ExecResponse, error) {
	response := ExecResponse{task: task}
	for _, opt := range options {
		err := opt(&response)
		if err != nil {
			return nil, err
		}
	}
	return &response, nil
}

func (r *ExecResponse) Metadata() ucan.Container {
	return r.metadata
}

func (r *ExecResponse) Receipt() ucan.Receipt {
	return r.receipt
}

// selfEncodingFailure is an error that encodes its own failure model: a named
// error carrying fields beyond the name and message a handler's caller needs to
// act on (say the region a request must be re-sent to). [ExecResponse.SetFailure]
// marshals one with its own encoder, so those fields reach the wire.
type selfEncodingFailure interface {
	errors.Named
	cbg.CBORMarshaler
}

// SetFailure issues and sets a receipt reporting that the task failed with x.
//
// An error that encodes its own CBOR is marshaled by itself, whether it is x or
// an error x wraps, so a failure carrying fields of its own keeps them. Any other
// error is reported as a name and a message: the name of the first [errors.Named]
// in the chain ("UnknownError" if there is none) and x's full message, wrapping
// context included.
func (r *ExecResponse) SetFailure(x error) error {
	if r.issuer == nil {
		return fmt.Errorf("cannot issue receipt: missing signer")
	}
	var errVal cbg.CBORMarshaler
	var selfEncoding selfEncodingFailure
	if cmx, ok := x.(cbg.CBORMarshaler); ok {
		errVal = cmx
	} else if errors.As(x, &selfEncoding) {
		errVal = selfEncoding
	} else {
		name := "UnknownError"
		var namedErr errors.Named
		if errors.As(x, &namedErr) {
			name = namedErr.Name()
		}
		errVal = datamodel.Map{
			"name":    name,
			"message": x.Error(),
		}
	}
	rcpt, err := receipt.IssueErr(r.issuer, r.task, errVal, r.receiptOptions()...)
	if err != nil {
		return err
	}
	r.receipt = rcpt
	return nil
}

func (r *ExecResponse) SetMetadata(meta ucan.Container) error {
	r.metadata = meta
	return nil
}

func (r *ExecResponse) SetReceipt(receipt ucan.Receipt) error {
	if receipt.Ran() != r.task {
		return fmt.Errorf("cannot set receipt: task mismatch (expected %s, got %s)", r.task, receipt.Ran())
	}
	r.receipt = receipt
	return nil
}

func (r *ExecResponse) SetIssuer(issuer ucan.Issuer) error {
	r.issuer = issuer
	return nil
}

func (r *ExecResponse) SetSuccess(ok cbg.CBORMarshaler) error {
	if r.issuer == nil {
		return fmt.Errorf("cannot issue receipt: missing issuer")
	}
	rcpt, err := receipt.IssueOK(r.issuer, r.task, ok, r.receiptOptions()...)
	if err != nil {
		return err
	}
	r.receipt = rcpt
	return nil
}

// receiptOptions builds the receipt issuance options from the response
// configuration.
func (r *ExecResponse) receiptOptions() []receipt.Option {
	var opts []receipt.Option
	if r.receiptTimestamp {
		opts = append(opts, receipt.WithIssuedAt(ucan.Now()))
	}
	if r.receiptExpiration != nil {
		opts = append(opts, receipt.WithExpiration(*r.receiptExpiration))
	}
	return opts
}

var _ Response = (*ExecResponse)(nil)
