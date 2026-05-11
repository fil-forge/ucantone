package bindexec_test

import (
	"bytes"
	"testing"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/bindexec"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/result"
	"github.com/fil-forge/ucantone/testutil"
	tdm "github.com/fil-forge/ucantone/testutil/datamodel"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestHandler(t *testing.T) {
	alice := testutil.RandomSigner(t)
	handler := bindexec.NewHandler(func(req *bindexec.Request[*tdm.TestObject], res *bindexec.Response[*tdm.TestObject2]) error {
		args := req.Task().BindArguments()
		require.Equal(t, args.Bytes, []byte{0x01, 0x02, 0x03})
		return res.SetSuccess(&tdm.TestObject2{Str: "testy"})
	})

	inv, err := invocation.Invoke(
		alice,
		alice,
		"/test/handler",
		datamodel.Map{"bytes": []byte{0x01, 0x02, 0x03}},
	)
	require.NoError(t, err)

	req := execution.NewRequest(t.Context(), inv)
	require.NoError(t, err)

	res, err := execution.NewResponse(inv.Task().Link(), execution.WithSigner(alice))
	require.NoError(t, err)

	err = handler(req, res)
	require.NoError(t, err)
	require.NotNil(t, res)

	okBytes, errBytes := result.Unwrap(res.Receipt().Out())
	require.Nil(t, errBytes)
	require.NotNil(t, okBytes)

	var got tdm.TestObject2
	require.NoError(t, got.UnmarshalCBOR(bytes.NewReader(okBytes)))
	require.Equal(t, "testy", got.Str)
}
