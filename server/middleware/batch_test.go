package middleware_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/server/middleware"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
)

func TestBatchRoute(t *testing.T) {
	service := testutil.RandomIssuer(t)
	agent := testutil.RandomIssuer(t)
	other := testutil.RandomIssuer(t)

	// item builds an invocation and an empty response for it.
	item := func(t *testing.T, issuer ucan.Issuer, subject ucan.Principal) execution.Batch {
		inv, err := invocation.Invoke(issuer, subject.DID(), testutil.ConsoleLogCommand, nil, invocation.WithAudience(service.DID()))
		require.NoError(t, err)
		res, err := execution.NewResponse(inv.Task().Link(), execution.WithIssuer(service))
		require.NoError(t, err)
		return execution.Batch{Request: execution.NewRequest(t.Context(), inv), Response: res}
	}

	type pair struct {
		issuer  ucan.Issuer
		subject ucan.Principal
	}
	for name, tc := range map[string]struct {
		mw                 middleware.Middleware
		accepted, rejected pair
	}{
		"NotSelfSigned": {middleware.NotSelfSigned(), pair{agent, service}, pair{agent, agent}},
		"OnlySubject":   {middleware.OnlySubject(service.DID()), pair{agent, service}, pair{agent, other}},
		"OnlyIssuer":    {middleware.OnlyIssuer(agent.DID()), pair{agent, service}, pair{other, service}},
	} {
		t.Run(name+" passes the accepted invocations and fails the rest", func(t *testing.T) {
			var got []execution.Batch
			routes := middleware.Apply([]server.Route{server.NewBatchRoute(testutil.ConsoleLogCommand, func(items []execution.Batch) error {
				got = items
				for _, item := range items {
					if err := item.Response.SetSuccess(datamodel.Map{}); err != nil {
						return err
					}
				}
				return nil
			})}, tc.mw)

			items := []execution.Batch{
				item(t, tc.accepted.issuer, tc.accepted.subject),
				item(t, tc.rejected.issuer, tc.rejected.subject),
			}
			require.NoError(t, routes[0].Handler(items))
			require.Len(t, got, 1)
			require.Equal(t, items[0], got[0])
			require.False(t, items[0].Response.Receipt().Out().IsErr())
			require.True(t, items[1].Response.Receipt().Out().IsErr())
		})
	}

	t.Run("the batch handler is not called when every invocation is rejected", func(t *testing.T) {
		called := false
		routes := middleware.Apply([]server.Route{server.NewBatchRoute(testutil.ConsoleLogCommand, func(items []execution.Batch) error {
			called = true
			return nil
		})}, middleware.OnlyIssuer(agent.DID()))

		items := []execution.Batch{item(t, other, service), item(t, other, other)}
		require.NoError(t, routes[0].Handler(items))
		require.False(t, called)
		for _, item := range items {
			require.True(t, item.Response.Receipt().Out().IsErr())
		}
	})
}
