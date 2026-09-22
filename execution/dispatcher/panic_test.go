package dispatcher_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
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
			executor := dispatcher.New(service, dispatcher.WithLogger(slog.New(slog.DiscardHandler)))
			executor.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
				panic(value)
			})

			resp, err := executor.Execute(execution.NewRequest(t.Context(), inv))
			require.NoError(t, err)

			_, x := resp.Receipt().Out().Unpack()
			require.Equal(t, map[string]any{
				"name":    execution.HandlerExecutionErrorName,
				"message": `"/console/log" handler execution error: handler panicked: boom`,
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

		executor := dispatcher.New(service, dispatcher.WithLogger(slog.New(slog.DiscardHandler)))
		executor.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
			panic(nil)
		})

		resp, err := executor.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)

		_, x := resp.Receipt().Out().Unpack()
		require.Equal(t, map[string]any{
			"name":    execution.HandlerExecutionErrorName,
			"message": `"/console/log" handler execution error: handler panicked: <nil>`,
		}, testutil.ResultMap(t, x))
	})

	t.Run("a huge panic value is truncated so the receipt still encodes", func(t *testing.T) {
		executor := dispatcher.New(service, dispatcher.WithLogger(slog.New(slog.DiscardHandler)))
		huge := strings.Repeat("x", 3*dispatcher.MaxPanicMessageLength)
		executor.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
			panic(huge)
		})

		resp, err := executor.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)

		_, x := resp.Receipt().Out().Unpack()
		require.Equal(t,
			`"/console/log" handler execution error: handler panicked: `+huge[:dispatcher.MaxPanicMessageLength]+"…[truncated]",
			testutil.ResultMap(t, x)["message"])
	})

	t.Run("the receipt expires like one for a returned error", func(t *testing.T) {
		executor := dispatcher.New(service, dispatcher.WithLogger(slog.New(slog.DiscardHandler)))
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

	t.Run("logs the panic with command, task and stack", func(t *testing.T) {
		var buf bytes.Buffer
		executor := dispatcher.New(service, dispatcher.WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))
		executor.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
			panic("boom")
		})

		_, err := executor.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)

		logged := buf.String()
		for _, want := range []string{
			`level=ERROR`,
			`msg="handler panicked"`,
			`command=/console/log`,
			`task=` + inv.Task().Link().String(),
			`panic=boom`,
			`stack="goroutine `,
		} {
			require.Contains(t, logged, want)
		}
	})

	t.Run("a panic in the handler does not affect other invocations", func(t *testing.T) {
		executor := dispatcher.New(service, dispatcher.WithLogger(slog.New(slog.DiscardHandler)))
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

	t.Run("WithLogger(nil) panics", func(t *testing.T) {
		require.PanicsWithValue(t, "dispatcher.WithLogger: logger must not be nil", func() {
			dispatcher.WithLogger(nil)
		})
	})
}
