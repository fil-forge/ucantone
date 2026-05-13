package bindexec

import (
	"bytes"
	"reflect"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
)

type Task[A Arguments] struct {
	*invocation.Task
	args A
}

// NewTask constructs a typed task. argsBytes must be the raw CBOR encoding of
// the args (typically obtained from [invocation.Invocation.ArgumentsBytes]);
// the bytes are decoded directly into the typed argument struct A via cborgen.
func NewTask[A Arguments](
	subject did.DID,
	command ucan.Command,
	argsBytes []byte,
	nonce []byte,
) (*Task[A], error) {
	var args A
	// if args is a pointer type, allocate the underlying value so
	// UnmarshalCBOR has a non-nil pointer to write into.
	typ := reflect.TypeOf(args)
	if typ != nil && typ.Kind() == reflect.Ptr {
		args = reflect.New(typ.Elem()).Interface().(A)
	}
	if err := args.UnmarshalCBOR(bytes.NewReader(argsBytes)); err != nil {
		return nil, err
	}
	task, err := invocation.NewTask(subject, command, argsBytes, nonce)
	if err != nil {
		return nil, err
	}
	return &Task[A]{Task: task, args: args}, nil
}

// Arguments returns the arguments bound to the type for this task.
func (t *Task[A]) Arguments() A {
	return t.args
}

var _ ucan.Task = (*Task[Arguments])(nil)
