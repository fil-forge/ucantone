package dispatcher_test

import (
	"context"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/dispatcher"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/validator"
	"github.com/stretchr/testify/require"
)

// A DID resolver is the validation extension point most likely to be supplied
// by an application, so it stands in for every piece of validation code that
// can panic outside the handler.
func TestDispatcherValidationPanic(t *testing.T) {
	service := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)

	inv, err := invocation.Invoke(
		alice,
		alice.DID(),
		testutil.ConsoleLogCommand,
		datamodel.Map{"message": "Hello, World!"},
		invocation.WithAudience(service.DID()),
	)
	require.NoError(t, err)

	panickingResolver := validator.WithDIDResolver(did.ResolverFunc(func(context.Context, did.DID) (did.Document, error) {
		panic("boom")
	}))

	newExecutor := func(t *testing.T, options ...dispatcher.Option) *dispatcher.Dispatcher {
		options = append(options, dispatcher.WithValidationOptions(panickingResolver))
		executor := dispatcher.New(service, options...)
		executor.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
			t.Error("handler must not run when validation panics")
			return nil
		})
		return executor
	}

	t.Run("issues an execution panic error receipt", func(t *testing.T) {
		executor := newExecutor(t, dispatcher.WithPanicLogger(discardPanics))

		resp, err := executor.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)

		_, x := resp.Receipt().Out().Unpack()
		require.Equal(t, map[string]any{
			"name":    execution.ExecutionPanicErrorName,
			"message": `"/console/log" execution panicked`,
		}, testutil.ResultMap(t, x))
	})

	t.Run("the receipt expires like one for a handler error", func(t *testing.T) {
		executor := newExecutor(t, dispatcher.WithPanicLogger(discardPanics))

		before := ucan.Now()
		resp, err := executor.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)

		ttl := ucan.UnixTimestamp(dispatcher.DefaultHandlerErrorReceiptTTL.Seconds())
		exp := resp.Receipt().Expiration()
		require.NotNil(t, exp)
		require.GreaterOrEqual(t, *exp, before+ttl)
		require.LessOrEqual(t, *exp, ucan.Now()+ttl)
	})

	t.Run("calls the panic logger with the request and the panic value", func(t *testing.T) {
		type call struct {
			task  string
			value any
		}
		var calls []call
		executor := newExecutor(t, dispatcher.WithPanicLogger(func(req execution.Request, value any) {
			calls = append(calls, call{req.Invocation().Task().Link().String(), value})
		}))

		_, err := executor.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)

		require.Equal(t, []call{{inv.Task().Link().String(), "boom"}}, calls)
	})
}
