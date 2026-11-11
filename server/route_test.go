package server_test

import (
	"testing"

	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/stretchr/testify/require"
)

func TestHandleRouteRejectsARouteWithNoHandler(t *testing.T) {
	srv := server.NewHTTP(testutil.RandomIssuer(t))
	require.PanicsWithValue(t, `server.HandleRoute: route for "/test/echo" has no handler`, func() {
		srv.HandleRoute(server.Route{Command: testutil.TestEchoCommand})
	})
}
