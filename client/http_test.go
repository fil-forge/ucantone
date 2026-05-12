package client_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestHTTPClient(t *testing.T) {
	service := testutil.RandomSigner(t)
	alice := testutil.RandomSigner(t)

	t.Run("invocation execution round trip", func(t *testing.T) {
		server := server.NewHTTP(service)

		server.Handle(testutil.TestEchoCapability, func(req execution.Request, res execution.Response) error {
			return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
		})

		c, err := client.NewHTTP(
			testutil.Must(url.Parse("http://localhost"))(t),
			client.WithHTTPClient(&http.Client{Transport: server}),
		)
		require.NoError(t, err)

		inv, err := testutil.TestEchoCapability.Invoke(
			alice,
			alice,
			datamodel.Map{"message": "echo!"},
			invocation.WithAudience(service),
		)
		require.NoError(t, err)

		res, err := c.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)

		o, x := res.Receipt().Out().Unpack()
		require.Nil(t, x)
		require.NotNil(t, o)
		require.Equal(t, "echo!", testutil.ResultMap(t, o)["message"])
	})
}
