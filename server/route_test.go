package server_test

import (
	"testing"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestHandleRouteRejectsARouteWithNoHandler(t *testing.T) {
	srv := server.NewHTTP(testutil.RandomIssuer(t))
	require.PanicsWithValue(t, `server.HandleRoute: route for "/test/echo" has no handler`, func() {
		srv.HandleRoute(server.Route{Command: testutil.TestEchoCommand})
	})
}

func TestHandleRouteRegistersOnlyTheBatchHandlerWhenARouteHasBoth(t *testing.T) {
	service := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)
	srv := server.NewHTTP(service)
	singleCalled := false
	srv.HandleRoute(server.Route{
		Command: testutil.TestEchoCommand,
		Handler: func(req execution.Request, res execution.Response) error {
			singleCalled = true
			return res.SetSuccess(datamodel.Map{})
		},
		BatchHandler: func(items []execution.Batch) error {
			for _, item := range items {
				if err := item.Response.SetSuccess(datamodel.Map{}); err != nil {
					return err
				}
			}
			return nil
		},
	})

	inv, err := invocation.Invoke(alice, alice.DID(), testutil.TestEchoCommand, datamodel.Map{}, invocation.WithAudience(service.DID()))
	require.NoError(t, err)
	res, err := srv.Execute(execution.NewRequest(t.Context(), inv))
	require.NoError(t, err)
	require.False(t, res.Receipt().Out().IsErr())
	require.False(t, singleCalled)
}
