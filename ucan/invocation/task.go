package invocation

import (
	"bytes"
	"fmt"

	cid "github.com/ipfs/go-cid"
	multihash "github.com/multiformats/go-multihash/core"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	idm "github.com/fil-forge/ucantone/ucan/invocation/datamodel"
)

type Task struct {
	link     cid.Cid
	bytes    []byte
	sub      did.DID
	cmd      ucan.Command
	argBytes []byte
	nnc      ucan.Nonce
}

// NewTask constructs a task from its component fields. argsBytes must be the
// raw CBOR encoding of the args (typically obtained from
// [Invocation.ArgumentsBytes] or by marshaling a typed cborgen struct directly).
func NewTask(
	subject did.DID,
	command ucan.Command,
	argsBytes []byte,
	nonce ucan.Nonce,
) (*Task, error) {
	if len(argsBytes) == 0 {
		argsBytes = []byte{0xa0}
	}
	taskModel := idm.TaskModel{
		Sub:   subject,
		Cmd:   command,
		Args:  datamodel.NewRaw(argsBytes),
		Nonce: nonce,
	}

	var taskBuf bytes.Buffer
	err := taskModel.MarshalCBOR(&taskBuf)
	if err != nil {
		return nil, fmt.Errorf("marshaling task CBOR: %w", err)
	}
	link, err := cid.V1Builder{
		Codec:  dagcbor.Code,
		MhType: multihash.SHA2_256,
	}.Sum(taskBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("hashing task bytes: %w", err)
	}

	return &Task{link, taskBuf.Bytes(), subject, command, argsBytes, nonce}, nil
}

// ArgumentsBytes returns the raw CBOR bytes of the args field.
func (t *Task) ArgumentsBytes() []byte {
	return t.argBytes
}

func (t *Task) Bytes() []byte {
	return t.bytes
}

func (t *Task) Command() ucan.Command {
	return t.cmd
}

func (t *Task) Link() cid.Cid {
	return t.link
}

func (t *Task) Nonce() ucan.Nonce {
	return t.nnc
}

func (t *Task) Subject() did.DID {
	return t.sub
}

var _ ucan.Task = (*Task)(nil)
