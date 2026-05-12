package testutil

import (
	"testing"

	hdm "github.com/fil-forge/ucantone/testutil/datamodel"
)

// RandomArgs returns a populated *hdm.TestArgs. It implements [cbg.CBORMarshaler]
// (and the dag-json equivalent) and can be passed directly to
// invocation.Invoke or marshalled into envelope bytes.
func RandomArgs(t *testing.T) *hdm.TestArgs {
	var list []string
	for range RandomBytes(t, 1)[0] {
		list = append(list, RandomCID(t).String())
	}
	return &hdm.TestArgs{
		ID:    RandomDID(t),
		Link:  RandomCID(t),
		Str:   RandomCID(t).String(),
		Num:   int64(RandomBytes(t, 1)[0]),
		Bytes: RandomBytes(t, 32),
		Obj: hdm.TestObject{
			Bytes: RandomBytes(t, 32),
		},
		List: list,
	}
}
