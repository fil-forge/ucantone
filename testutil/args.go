package testutil

import (
	"testing"

	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	hdm "github.com/fil-forge/ucantone/testutil/datamodel"
	"github.com/stretchr/testify/require"
)

func RandomArgs(t *testing.T) ipld.Map {
	var list []string
	for range RandomBytes(t, 1)[0] {
		list = append(list, RandomCID(t).String())
	}
	m := datamodel.Map{}
	err := datamodel.Rebind(&hdm.TestArgs{
		ID:    RandomDID(t),
		Link:  RandomCID(t),
		Str:   RandomCID(t).String(),
		Num:   int64(RandomBytes(t, 1)[0]),
		Bytes: RandomBytes(t, 32),
		Obj: hdm.TestObject{
			Bytes: RandomBytes(t, 32),
		},
		List: list,
	}, &m)
	require.NoError(t, err)
	return m
}
