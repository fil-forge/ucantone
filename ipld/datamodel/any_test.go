package datamodel_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/filecoin-project/go-state-types/big"
	"github.com/stretchr/testify/require"
)

func TestAny(t *testing.T) {
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

// big.Int is CBOR only (not supported in DAG-JSON), so it round-trips through
// its own test rather than the shared list above.
func TestAnyBigInt(t *testing.T) {
	values := []big.Int{
		big.NewInt(0),
		big.NewInt(138),
		big.NewInt(-138),
		big.MustFromString("340282366920938463463374607431768211457"),  // > maxUint64, positive
		big.MustFromString("-340282366920938463463374607431768211457"), // < minInt64, negative
	}

	for _, v := range values {
		t.Run(fmt.Sprintf("dag-cbor %s", v), func(t *testing.T) {
			initial := datamodel.NewAny(v)

			var buf bytes.Buffer
			err := initial.MarshalCBOR(&buf)
			require.NoError(t, err)

			var decoded datamodel.Any
			err = decoded.UnmarshalCBOR(&buf)
			require.NoError(t, err)
			require.Equal(t, v, decoded.Value)
		})

		t.Run(fmt.Sprintf("dag-json unsupported %s", v), func(t *testing.T) {
			var buf bytes.Buffer
			err := datamodel.NewAny(v).MarshalDagJSON(&buf)
			require.Error(t, err)
		})
	}
}
