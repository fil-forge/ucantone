package promise_test

import (
	"bytes"
	"fmt"
	"testing"

	jsg "github.com/alanshaw/dag-json-gen"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/promise"
	"github.com/stretchr/testify/require"
	cbg "github.com/whyrusleeping/cbor-gen"
)

type dagMarshalable interface {
	cbg.CBORMarshaler
	cbg.CBORUnmarshaler
	jsg.DagJsonMarshaler
	jsg.DagJsonUnmarshaler
}

func TestPromise(t *testing.T) {
	values := []dagMarshalable{
		&promise.AwaitAny{Task: testutil.RandomCID(t)},
		&promise.AwaitOK{Task: testutil.RandomCID(t)},
		&promise.AwaitError{Task: testutil.RandomCID(t)},
	}

	for _, v := range values {
		t.Run(fmt.Sprintf("dag-cbor %T", v), func(t *testing.T) {
			var buf bytes.Buffer
			err := v.MarshalCBOR(&buf)
			require.NoError(t, err)

			err = v.UnmarshalCBOR(&buf)
			require.NoError(t, err)
		})

		t.Run(fmt.Sprintf("dag-json %T", v), func(t *testing.T) {
			var buf bytes.Buffer
			err := v.MarshalDagJSON(&buf)
			require.NoError(t, err)

			t.Log(buf.String())

			err = v.UnmarshalDagJSON(&buf)
			require.NoError(t, err)
		})
	}
}
