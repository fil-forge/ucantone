package binding_test

import (
	"testing"

	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/testutil"
	tdm "github.com/fil-forge/ucantone/testutil/datamodel"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestBatchHandler(t *testing.T) {
	alice := testutil.RandomIssuer(t)
	cmd := binding.Bind[*tdm.TestObject, *tdm.TestObject2](command.MustParse("/test/batch"))

	item := func(t *testing.T, args datamodel.Map) execution.Batch {
		inv, err := invocation.Invoke(alice, alice.DID(), cmd.Command, args)
		require.NoError(t, err)
		res, err := execution.NewResponse(inv.Task().Link(), execution.WithIssuer(alice))
		require.NoError(t, err)
		return execution.Batch{Request: execution.NewRequest(t.Context(), inv), Response: res}
	}

	t.Run("decodes each invocation's arguments", func(t *testing.T) {
		var got [][]byte
		handler := cmd.BatchHandler(func(items []binding.Batch[*tdm.TestObject, *tdm.TestObject2]) error {
			for _, it := range items {
				got = append(got, it.Request.Task().Arguments().Bytes)
				if err := it.Response.SetSuccess(&tdm.TestObject2{Str: "ok"}); err != nil {
					return err
				}
			}
			return nil
		})

		items := []execution.Batch{
			item(t, datamodel.Map{"bytes": []byte{1}}),
			item(t, datamodel.Map{"bytes": []byte{2}}),
		}
		require.NoError(t, handler(items))
		require.Equal(t, [][]byte{{1}, {2}}, got)
		for _, it := range items {
			out, err := cmd.Unpack(it.Response.Receipt())
			require.NoError(t, err)
			require.Equal(t, "ok", out.Str)
		}
	})

	t.Run("fails malformed arguments and leaves them out", func(t *testing.T) {
		var got int
		handler := binding.NewBatchHandler(func(items []binding.Batch[*tdm.TestObject, *tdm.TestObject2]) error {
			got = len(items)
			for _, it := range items {
				if err := it.Response.SetSuccess(&tdm.TestObject2{}); err != nil {
					return err
				}
			}
			return nil
		})

		items := []execution.Batch{
			item(t, datamodel.Map{"bytes": []byte{1}}),
			item(t, datamodel.Map{"bytes": "not bytes"}),
		}
		require.NoError(t, handler(items))
		require.Equal(t, 1, got)
		_, x := items[1].Response.Receipt().Out().Unpack()
		require.Equal(t, binding.MalformedArgumentsErrorName, testutil.ResultMap(t, x)["name"])
	})

	t.Run("does not call the handler when no invocation decodes", func(t *testing.T) {
		called := false
		handler := binding.NewBatchHandler(func(items []binding.Batch[*tdm.TestObject, *tdm.TestObject2]) error {
			called = true
			return nil
		})
		require.NoError(t, handler([]execution.Batch{item(t, datamodel.Map{"bytes": 1})}))
		require.False(t, called)
	})

	t.Run("BatchRoute carries the command and a batch handler", func(t *testing.T) {
		route := cmd.BatchRoute(func(items []binding.Batch[*tdm.TestObject, *tdm.TestObject2]) error { return nil })
		require.Equal(t, cmd.Command, route.Command)
		require.Nil(t, route.Handler)
		require.NotNil(t, route.BatchHandler)
	})
}
