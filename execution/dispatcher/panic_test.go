package dispatcher_test

import (
	"errors"
	"testing"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/dispatcher"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestDispatcherHandlerPanic(t *testing.T) {
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

	panicValues := map[string]any{
		"a string": "boom",
		"an error": errors.New("boom"),
	}

	for desc, value := range panicValues {
		t.Run("issues a handler execution error receipt when the handler panics with "+desc, func(t *testing.T) {
			executor := dispatcher.New(service, dispatcher.WithPanicLogger(discardPanics))
			executor.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
				panic(value)
			})

			resp, err := executor.Execute(execution.NewRequest(t.Context(), inv))
			require.NoError(t, err)

			_, x := resp.Receipt().Out().Unpack()
			require.Equal(t, map[string]any{
				"name":    execution.HandlerExecutionErrorName,
				"message": `"/console/log" handler execution error: handler panicked`,
			}, testutil.ResultMap(t, x))
		})
	}

	t.Run("panic(nil) recovered as nil still fails the task", func(t *testing.T) {
		// Under this setting the runtime hands recover() a nil for panic(nil),
		// which is indistinguishable from no panic by value alone.
		t.Setenv("GODEBUG", "panicnil=1")
		var recovered any = "unset"
		func() {
			defer func() { recovered = recover() }()
			panic(nil)
		}()
		require.Nil(t, recovered, "GODEBUG=panicnil=1 did not take effect at runtime")

		executor := dispatcher.New(service, dispatcher.WithPanicLogger(discardPanics))
		executor.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
			panic(nil)
		})

		resp, err := executor.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)

		_, x := resp.Receipt().Out().Unpack()
		require.Equal(t, map[string]any{
			"name":    execution.HandlerExecutionErrorName,
			"message": `"/console/log" handler execution error: handler panicked`,
		}, testutil.ResultMap(t, x))
	})

	t.Run("the receipt expires like one for a returned error", func(t *testing.T) {
		executor := dispatcher.New(service, dispatcher.WithPanicLogger(discardPanics))
		executor.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
			panic("boom")
		})

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
		executor := dispatcher.New(service, dispatcher.WithPanicLogger(func(req execution.Request, value any) {
			calls = append(calls, call{req.Invocation().Task().Link().String(), value})
		}))
		executor.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
			panic("boom")
		})

		_, err := executor.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)

		require.Equal(t, []call{{inv.Task().Link().String(), "boom"}}, calls)
	})

	t.Run("a panic in the handler does not affect other invocations", func(t *testing.T) {
		executor := dispatcher.New(service, dispatcher.WithPanicLogger(discardPanics))
		executor.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
			panic("boom")
		})
		executor.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
		})
		echoInv, err := invocation.Invoke(alice, alice.DID(), testutil.TestEchoCommand, datamodel.Map{"message": "echo!"}, invocation.WithAudience(service.DID()))
		require.NoError(t, err)

		_, err = executor.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)
		resp, err := executor.Execute(execution.NewRequest(t.Context(), echoInv))
		require.NoError(t, err)

		o, _ := resp.Receipt().Out().Unpack()
		require.Equal(t, "echo!", testutil.ResultMap(t, o)["message"])
	})

	t.Run("WithPanicLogger(nil) panics", func(t *testing.T) {
		require.PanicsWithValue(t, "dispatcher.WithPanicLogger: logger must not be nil", func() {
			dispatcher.WithPanicLogger(nil)
		})
	})
}

func discardPanics(execution.Request, any) {}
