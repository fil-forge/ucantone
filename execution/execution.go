package execution

import (
	"context"

	"github.com/fil-forge/ucantone/ucan"
	cbg "github.com/whyrusleeping/cbor-gen"
)

type Request interface {
	Context() context.Context
	// Invocation that should be executed.
	Invocation() ucan.Invocation
	// Metadata provides additional information about the invocation.
	Metadata() ucan.Container
}

type Response interface {
	// Receipt for the executed task.
	Receipt() ucan.Receipt
	// SetReceipt sets the receipt for the executed task.
	SetReceipt(ucan.Receipt) error
	// SetSuccess issues a receipt with a successful result for the executed
	// task and sets it on the response. The ok value is any
	// cborgen-marshalable type whose schema matches what the task expects to
	// produce.
	SetSuccess(ok cbg.CBORMarshaler) error
	// SetFailure issues a receipt with a failure result for the executed task
	// and sets it on the response.
	SetFailure(error) error
	// Metadata provides additional information about the response.
	Metadata() ucan.Container
	// SetMetadata sets additional information about the response.
	SetMetadata(ucan.Container) error
}

// Executor executes UCAN invocations. In order to execute an invocation, proof
// chains must be validated and delegation policies matched. Hence a UCAN
// executor is responsible for both validation and execution of invocations.
type Executor interface {
	Execute(Request) (Response, error)
}

// HandlerFunc is a function that can handle a specific UCAN invocation.
type HandlerFunc = func(Request, Response) error
