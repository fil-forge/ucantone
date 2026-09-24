package middleware_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fil-forge/ucantone/did"
	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/server/middleware"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
)

// wrap applies the middleware to a command that records whether it ran.
func wrap(t *testing.T, ran *bool, mw ...middleware.Middleware) server.Route {
	t.Helper()
	routes := middleware.Apply([]server.Route{{
		Command: testutil.ConsoleLogCommand,
		Handler: func(req execution.Request, res execution.Response) error {
			*ran = true
			return nil
		},
	}}, mw...)
	require.Len(t, routes, 1)
	return routes[0]
}

// execute runs the route's handler over an invocation of its command and returns
// the failure the receipt carries, or nil when the handler set no failure.
func execute(t *testing.T, route server.Route, executor ucan.Issuer, issuer ucan.Issuer, subject did.DID) error {
	t.Helper()
	inv, err := invocation.Invoke(issuer, subject, route.Command, nil, invocation.WithAudience(executor.DID()))
	require.NoError(t, err)

	res, err := execution.NewResponse(inv.Task().Link(), execution.WithIssuer(executor))
	require.NoError(t, err)
	require.NoError(t, route.Handler(execution.NewRequest(t.Context(), inv), res))

	rcpt := res.Receipt()
	if rcpt == nil {
		return nil
	}
	out := rcpt.Out()
	if !out.IsErr() {
		return nil
	}
	_, errBytes := out.Unpack()
	var model edm.ErrorModel
	require.NoError(t, model.UnmarshalCBOR(bytes.NewReader(errBytes)))
	return model
}

func TestNotSelfSigned(t *testing.T) {
	service := testutil.RandomIssuer(t)
	agent := testutil.RandomIssuer(t)

	t.Run("rejects an invocation issued by its own subject", func(t *testing.T) {
		var ran bool
		err := execute(t, wrap(t, &ran, middleware.NotSelfSigned()), service, agent, agent.DID())
		require.ErrorIs(t, err, middleware.ErrSelfSignedInvocation)
		require.False(t, ran)
	})

	t.Run("runs the command when the issuer is not the subject", func(t *testing.T) {
		var ran bool
		err := execute(t, wrap(t, &ran, middleware.NotSelfSigned()), service, agent, service.DID())
		require.NoError(t, err)
		require.True(t, ran)
	})
}

func TestOnlySubject(t *testing.T) {
	service := testutil.RandomIssuer(t)
	agent := testutil.RandomIssuer(t)

	t.Run("rejects an invocation subjected to someone else", func(t *testing.T) {
		var ran bool
		err := execute(t, wrap(t, &ran, middleware.OnlySubject(service.DID())), service, agent, agent.DID())
		require.ErrorIs(t, err, middleware.ErrInvalidSubject)
		require.False(t, ran)
	})

	t.Run("runs the command when the subject matches", func(t *testing.T) {
		var ran bool
		err := execute(t, wrap(t, &ran, middleware.OnlySubject(service.DID())), service, agent, service.DID())
		require.NoError(t, err)
		require.True(t, ran)
	})
}

func TestOnlyIssuer(t *testing.T) {
	service := testutil.RandomIssuer(t)
	agent := testutil.RandomIssuer(t)

	t.Run("rejects an invocation from another issuer", func(t *testing.T) {
		var ran bool
		err := execute(t, wrap(t, &ran, middleware.OnlyIssuer(service.DID())), service, agent, service.DID())
		require.ErrorIs(t, err, middleware.ErrUnauthorized)
		require.False(t, ran)
	})

	t.Run("runs the command for the issuer's own self-signed invocation", func(t *testing.T) {
		var ran bool
		err := execute(t, wrap(t, &ran, middleware.OnlyIssuer(service.DID())), service, service, service.DID())
		require.NoError(t, err)
		require.True(t, ran)
	})
}

// TestApplyOrder checks that the first middleware is the outermost.
func TestApplyOrder(t *testing.T) {
	service := testutil.RandomIssuer(t)
	agent := testutil.RandomIssuer(t)

	var ran bool
	route := wrap(t, &ran, middleware.NotSelfSigned(), middleware.OnlySubject(service.DID()))
	err := execute(t, route, service, agent, agent.DID())
	require.ErrorIs(t, err, middleware.ErrSelfSignedInvocation, "the outermost check reports the rejection")
	require.False(t, ran)
}

// TestMiddlewareSeesTheRoute checks a middleware is handed the route it wraps,
// so it can read the command once rather than off every invocation.
func TestMiddlewareSeesTheRoute(t *testing.T) {
	service := testutil.RandomIssuer(t)
	agent := testutil.RandomIssuer(t)

	var seen ucan.Command
	record := func(route server.Route) server.Route {
		seen = route.Command
		return route
	}

	var ran bool
	route := wrap(t, &ran, middleware.Middleware(record))
	require.Equal(t, testutil.ConsoleLogCommand, seen, "the command is read when the middleware is applied")

	require.NoError(t, execute(t, route, service, agent, service.DID()))
	require.True(t, ran)
}

// TestApplyLeavesRoutesUnchanged checks Apply builds new routes rather than
// rewriting the handlers it was given.
func TestApplyLeavesRoutesUnchanged(t *testing.T) {
	service := testutil.RandomIssuer(t)
	agent := testutil.RandomIssuer(t)

	var ran bool
	original := []server.Route{{
		Command: testutil.ConsoleLogCommand,
		Handler: func(req execution.Request, res execution.Response) error {
			ran = true
			return nil
		},
	}}
	middleware.Apply(original, middleware.NotSelfSigned())

	err := execute(t, original[0], service, agent, agent.DID())
	require.NoError(t, err)
	require.True(t, ran, "the original route should still run its command")
}
