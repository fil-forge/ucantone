package bindexec

import (
	"reflect"

	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
)

type Task[A Arguments] struct {
	*invocation.Task
	args A
}

func NewTask[A Arguments](
	subject ucan.Subject,
	command ucan.Command,
	arguments ipld.Map,
	nonce ucan.Nonce,
) (*Task[A], error) {
	var args A
	// if args is a pointer type, then we need to create an instance of it because
	// rebind requires a non-nil pointer.
	typ := reflect.TypeOf(args)
	if typ.Kind() == reflect.Ptr {
		args = reflect.New(typ.Elem()).Interface().(A)
	}
	if err := datamodel.Rebind(datamodel.Map(arguments), args); err != nil {
		return nil, err
	}
	task, err := invocation.NewTask(subject, command, arguments, nonce)
	if err != nil {
		return nil, err
	}
	return &Task[A]{Task: task, args: args}, nil
}

// BindArguments returns the arguments bound to the type for this task.
func (t *Task[A]) BindArguments() A {
	return t.args
}

var _ ucan.Task = (*Task[Arguments])(nil)
