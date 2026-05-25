package datamodel_test

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/stretchr/testify/require"
)

func TestAny(t *testing.T) {
	gtMaxUint64, ok := big.NewInt(0).SetString("340282366920938463463374607431768211457", 10) // > maxUint64, positive
	require.True(t, ok)

	ltMinInt64, ok := big.NewInt(0).SetString("-340282366920938463463374607431768211457", 10) // < minInt64, negative
	require.True(t, ok)

	values := []any{
		int64(138),
		true,
		false,
		nil,
		testutil.RandomCID(t),
		"test",
		[]byte{1, 2, 3},
		[]string{"one", "two", "three"},
		map[string]ipld.Any{"bytes": []byte{1}},
		map[string]ipld.Any{
			"str":   "X",
			"bytes": []byte{2},
		},
		gtMaxUint64,
		ltMinInt64,
		// map[string]cid.Cid{
		// 	"await/ok": testutil.RandomCID(t),
		// },
	}

	for _, v := range values {
		t.Run(fmt.Sprintf("dag-cbor %T", v), func(t *testing.T) {
			initial := datamodel.NewAny(v)

			var buf bytes.Buffer
			err := initial.MarshalCBOR(&buf)
			require.NoError(t, err)

			var decodedCBOR datamodel.Any
			err = decodedCBOR.UnmarshalCBOR(&buf)
			require.NoError(t, err)
			require.Equal(t, v, decodedCBOR.Value)
		})

		t.Run(fmt.Sprintf("dag-json %T", v), func(t *testing.T) {
			initial := datamodel.NewAny(v)

			var buf bytes.Buffer
			err := initial.MarshalDagJSON(&buf)
			require.NoError(t, err)

			t.Log(buf.String())

			var decodedJSON datamodel.Any
			err = decodedJSON.UnmarshalDagJSON(&buf)
			require.NoError(t, err)
			require.Equal(t, v, decodedJSON.Value)
		})
	}
}
