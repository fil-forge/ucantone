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
	signer           ucan.Signer
	task             cid.Cid
	receipt          ucan.Receipt
	metadata         ucan.Container
	receiptTimestamp bool
}

type ResponseOption func(r *ExecResponse) error

func WithSigner(signer ucan.Signer) ResponseOption {
	return func(resp *ExecResponse) error {
		resp.signer = signer
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

func (r *ExecResponse) SetFailure(x error) error {
	if r.signer == nil {
		return fmt.Errorf("cannot issue receipt: missing signer")
	}
	var errVal cbg.CBORMarshaler
	if cmx, ok := x.(cbg.CBORMarshaler); ok {
		errVal = cmx
	} else {
		name := "UnknownError"
		if nx, ok := x.(errors.Named); ok {
			name = nx.Name()
		}
		errVal = datamodel.Map{
			"name":    name,
			"message": x.Error(),
		}
	}
	rcpt, err := receipt.IssueErr(r.signer, r.task, errVal)
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

func (r *ExecResponse) SetSigner(signer ucan.Signer) error {
	r.signer = signer
	return nil
}

func (r *ExecResponse) SetSuccess(ok cbg.CBORMarshaler) error {
	if r.signer == nil {
		return fmt.Errorf("cannot issue receipt: missing signer")
	}
	rcpt, err := receipt.IssueOK(r.signer, r.task, ok)
	if err != nil {
		return err
	}
	r.receipt = rcpt
	return nil
}

var _ Response = (*ExecResponse)(nil)
