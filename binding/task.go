package binding

import (
	cbg "github.com/whyrusleeping/cbor-gen"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
)

type Task[Args cbg.CBORUnmarshaler] struct {
	*invocation.Task
	args Args
}

// NewTask constructs a typed task. argsBytes must be the raw CBOR encoding of
// the args (typically obtained from [invocation.Invocation.ArgumentsBytes]);
// the bytes are decoded directly into the typed argument struct Args via cborgen.
func NewTask[Args cbg.CBORUnmarshaler](
	subject did.DID,
	command ucan.Command,
	argsBytes []byte,
	nonce []byte,
) (*Task[Args], error) {
	args, err := decode[Args](argsBytes)
	if err != nil {
		return nil, err
	}
	task, err := invocation.NewTask(subject, command, argsBytes, nonce)
	if err != nil {
		return nil, err
	}
	return &Task[Args]{Task: task, args: args}, nil
}

// Arguments returns the arguments bound to the type for this task.
func (t *Task[Args]) Arguments() Args {
	return t.args
}

var _ ucan.Task = (*Task[cbg.CBORUnmarshaler])(nil)
