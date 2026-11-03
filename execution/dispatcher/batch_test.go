package dispatcher_test

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/dispatcher"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/server/middleware"
	"github.com/fil-forge/ucantone/testutil"
	tdm "github.com/fil-forge/ucantone/testutil/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestDispatcherBatchHandler(t *testing.T) {
	service := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)

	invoke := func(t *testing.T, cmd ucan.Command, args datamodel.Map, options ...invocation.Option) execution.Request {
		options = append([]invocation.Option{invocation.WithAudience(service.DID())}, options...)
		inv, err := invocation.Invoke(alice, alice.DID(), cmd, args, options...)
		require.NoError(t, err)
		return execution.NewRequest(t.Context(), inv)
	}
	echoRequests := func(t *testing.T, n int) []execution.Request {
		reqs := make([]execution.Request, n)
		for i := range n {
			reqs[i] = invoke(t, testutil.TestEchoCommand, datamodel.Map{"i": int64(i)})
		}
		return reqs
	}
	echoAll := func(items []execution.Batch) error {
		for _, item := range items {
			if err := item.Response.SetSuccess(testutil.ArgsMap(t, item.Request.Invocation())); err != nil {
				return err
			}
		}
		return nil
	}
	requireOK := func(t *testing.T, reqs []execution.Request, resps []execution.Response) {
		require.Len(t, resps, len(reqs))
		for i, res := range resps {
			require.Equal(t, reqs[i].Invocation().Task().Link(), res.Receipt().Ran())
			ok, x := res.Receipt().Out().Unpack()
			require.Nil(t, x)
			require.Equal(t, map[string]any(testutil.ArgsMap(t, reqs[i].Invocation())), map[string]any(testutil.ResultMap(t, ok)))
		}
	}
	requireFailure := func(t *testing.T, res execution.Response, name string) {
		_, x := res.Receipt().Out().Unpack()
		require.NotNil(t, x)
		require.Equal(t, name, testutil.ResultMap(t, x)["name"])
	}

	t.Run("calls the batch handler once with every invocation of its command", func(t *testing.T) {
		d := dispatcher.New(service)
		var calls [][]execution.Batch
		d.HandleBatch(testutil.TestEchoCommand, func(items []execution.Batch) error {
			calls = append(calls, items)
			return echoAll(items)
		})

		reqs := echoRequests(t, 5)
		resps, err := d.ExecuteAll(reqs)
		require.NoError(t, err)
		requireOK(t, reqs, resps)
		require.Len(t, calls, 1)
		require.Len(t, calls[0], 5)
	})

	t.Run("Execute runs a single invocation as a batch of one", func(t *testing.T) {
		d := dispatcher.New(service)
		var sizes []int
		d.HandleBatch(testutil.TestEchoCommand, func(items []execution.Batch) error {
			sizes = append(sizes, len(items))
			return echoAll(items)
		})

		reqs := echoRequests(t, 1)
		res, err := d.Execute(reqs[0])
		require.NoError(t, err)
		requireOK(t, reqs, []execution.Response{res})
		require.Equal(t, []int{1}, sizes)
	})

	t.Run("a later registration for a command replaces the earlier one", func(t *testing.T) {
		d := dispatcher.New(service)
		d.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			return errors.New("single handler called")
		})
		var batched int
		d.HandleBatch(testutil.TestEchoCommand, func(items []execution.Batch) error {
			batched += len(items)
			return echoAll(items)
		})

		reqs := echoRequests(t, 3)
		resps, err := d.ExecuteAll(reqs)
		require.NoError(t, err)
		requireOK(t, reqs, resps)
		require.Equal(t, 3, batched)
	})

	t.Run("commands without a batch handler run through their own handler", func(t *testing.T) {
		d := dispatcher.New(service)
		var batched int
		d.HandleBatch(testutil.TestEchoCommand, func(items []execution.Batch) error {
			batched += len(items)
			return echoAll(items)
		})
		var single sync.Map
		d.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
			single.Store(req.Invocation().Task().Link(), true)
			return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
		})

		reqs := []execution.Request{
			invoke(t, testutil.TestEchoCommand, datamodel.Map{"i": int64(0)}),
			invoke(t, testutil.ConsoleLogCommand, datamodel.Map{"message": "a"}),
			invoke(t, testutil.TestEchoCommand, datamodel.Map{"i": int64(1)}),
			invoke(t, testutil.ConsoleLogCommand, datamodel.Map{"message": "b"}),
		}
		resps, err := d.ExecuteAll(reqs)
		require.NoError(t, err)
		requireOK(t, reqs, resps)
		require.Equal(t, 2, batched)
		for _, i := range []int{1, 3} {
			_, ok := single.Load(reqs[i].Invocation().Task().Link())
			require.True(t, ok)
		}
	})

	t.Run("invalid invocations get their failure and stay out of the batch", func(t *testing.T) {
		d := dispatcher.New(service)
		var got []execution.Batch
		d.HandleBatch(testutil.TestEchoCommand, func(items []execution.Batch) error {
			got = items
			return echoAll(items)
		})

		valid := invoke(t, testutil.TestEchoCommand, datamodel.Map{"i": int64(0)})
		misaddressed := invoke(t, testutil.TestEchoCommand, datamodel.Map{"i": int64(1)}, invocation.WithAudience(testutil.RandomDID(t)))
		expired := invoke(t, testutil.TestEchoCommand, datamodel.Map{"i": int64(2)}, invocation.WithExpiration(ucan.Now()-60))

		resps, err := d.ExecuteAll([]execution.Request{valid, misaddressed, expired})
		require.NoError(t, err)
		requireOK(t, []execution.Request{valid}, resps[:1])
		requireFailure(t, resps[1], execution.InvalidAudienceErrorName)
		_, x := resps[2].Receipt().Out().Unpack()
		require.NotNil(t, x)
		require.Len(t, got, 1)
		require.Equal(t, valid.Invocation().Task().Link(), got[0].Request.Invocation().Task().Link())
	})

	t.Run("the batch handler is not called when no invocation is valid", func(t *testing.T) {
		d := dispatcher.New(service)
		called := false
		d.HandleBatch(testutil.TestEchoCommand, func(items []execution.Batch) error {
			called = true
			return nil
		})

		req := invoke(t, testutil.TestEchoCommand, datamodel.Map{}, invocation.WithAudience(testutil.RandomDID(t)))
		res, err := d.Execute(req)
		require.NoError(t, err)
		requireFailure(t, res, execution.InvalidAudienceErrorName)
		require.False(t, called)
	})

	t.Run("an error from the batch handler fails every task with a short-lived receipt", func(t *testing.T) {
		d := dispatcher.New(service)
		d.HandleBatch(testutil.TestEchoCommand, func(items []execution.Batch) error {
			// A receipt set before the error does not survive it.
			if err := echoAll(items[:1]); err != nil {
				return err
			}
			return errors.New("boom")
		})

		resps, err := d.ExecuteAll(echoRequests(t, 3))
		require.NoError(t, err)
		for _, res := range resps {
			requireFailure(t, res, execution.HandlerExecutionErrorName)
			require.NotNil(t, res.Receipt().Expiration())
		}
	})

	t.Run("a per-invocation handler's error or panic fails only its own task", func(t *testing.T) {
		d := dispatcher.New(service, dispatcher.WithPanicLogger(discardPanics))
		reqs := echoRequests(t, 3)
		failing, panicking := reqs[0].Invocation().Task().Link(), reqs[1].Invocation().Task().Link()
		d.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			switch req.Invocation().Task().Link() {
			case failing:
				return errors.New("boom")
			case panicking:
				panic("boom")
			}
			return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
		})

		resps, err := d.ExecuteAll(reqs)
		require.NoError(t, err)
		requireFailure(t, resps[0], execution.HandlerExecutionErrorName)
		require.NotNil(t, resps[0].Receipt().Expiration())
		requireFailure(t, resps[1], execution.ExecutionFailureErrorName)
		require.NotNil(t, resps[1].Receipt().Expiration())
		requireOK(t, reqs[2:], resps[2:])
	})

	t.Run("Each calls the handler for each invocation outside a dispatcher", func(t *testing.T) {
		var calls int
		handler := dispatcher.Each(func(req execution.Request, res execution.Response) error {
			calls++
			return nil
		})
		reqs := echoRequests(t, 2)
		items := make([]execution.Batch, len(reqs))
		for i, req := range reqs {
			res, err := execution.NewResponse(req.Invocation().Task().Link(), execution.WithIssuer(service))
			require.NoError(t, err)
			items[i] = execution.Batch{Request: req, Response: res}
		}
		require.NoError(t, handler(items))
		require.Equal(t, 2, calls)
	})

	t.Run("a failure a task already has survives a batch error", func(t *testing.T) {
		d := dispatcher.New(service)
		rejection := errors.New("rejected before the batch failed")
		d.HandleBatch(testutil.TestEchoCommand, func(items []execution.Batch) error {
			if err := items[0].Response.SetFailure(rejection); err != nil {
				return err
			}
			return errors.New("boom")
		})

		resps, err := d.ExecuteAll(echoRequests(t, 3))
		require.NoError(t, err)
		_, x := resps[0].Receipt().Out().Unpack()
		require.Equal(t, rejection.Error(), testutil.ResultMap(t, x)["message"])
		for _, res := range resps[1:] {
			requireFailure(t, res, execution.HandlerExecutionErrorName)
		}
	})

	t.Run("middleware and decoding rejections survive a batch error", func(t *testing.T) {
		d := dispatcher.New(service)
		route := binding.Bind[*tdm.TestObject, *tdm.TestObject2](testutil.TestEchoCommand).BatchRoute(
			func(items []binding.Batch[*tdm.TestObject, *tdm.TestObject2]) error {
				return errors.New("boom")
			},
		)
		route = middleware.Apply([]server.Route{route}, middleware.NotSelfSigned())[0]
		d.HandleBatch(route.Command, route.Handler)

		// alice is her own subject, so her invocation is self-signed.
		selfSigned := invoke(t, testutil.TestEchoCommand, datamodel.Map{"bytes": []byte{1}})
		bob := testutil.RandomIssuer(t)
		dlg := testutil.Must(delegation.Delegate(service, bob.DID(), service.DID(), testutil.TestEchoCommand))(t)
		bobInvokes := func(args datamodel.Map) execution.Request {
			inv := testutil.Must(invocation.Invoke(bob, service.DID(), testutil.TestEchoCommand, args,
				invocation.WithAudience(service.DID()), invocation.WithProofs(dlg.Link())))(t)
			return execution.NewRequest(t.Context(), inv, execution.WithDelegations(dlg))
		}
		malformed := bobInvokes(datamodel.Map{"bytes": "not bytes"})
		accepted := bobInvokes(datamodel.Map{"bytes": []byte{2}})

		resps, err := d.ExecuteAll([]execution.Request{selfSigned, malformed, accepted})
		require.NoError(t, err)
		requireFailure(t, resps[0], middleware.SelfSignedInvocationErrorName)
		requireFailure(t, resps[1], binding.MalformedArgumentsErrorName)
		requireFailure(t, resps[2], execution.HandlerExecutionErrorName)
	})

	t.Run("a panic in the batch handler fails every task and is logged once", func(t *testing.T) {
		var logged int
		d := dispatcher.New(service, dispatcher.WithPanicLogger(func(execution.Request, any) { logged++ }))
		d.HandleBatch(testutil.TestEchoCommand, func(items []execution.Batch) error {
			panic("boom")
		})

		resps, err := d.ExecuteAll(echoRequests(t, 3))
		require.NoError(t, err)
		for _, res := range resps {
			requireFailure(t, res, execution.ExecutionFailureErrorName)
		}
		require.Equal(t, 1, logged)
	})

	t.Run("a task the batch handler leaves without a receipt fails", func(t *testing.T) {
		d := dispatcher.New(service)
		d.HandleBatch(testutil.TestEchoCommand, func(items []execution.Batch) error {
			return echoAll(items[1:])
		})

		reqs := echoRequests(t, 3)
		resps, err := d.ExecuteAll(reqs)
		require.NoError(t, err)
		requireFailure(t, resps[0], execution.ExecutionFailureErrorName)
		requireOK(t, reqs[1:], resps[1:])
	})

	t.Run("the batch handler's changes to the items do not move responses", func(t *testing.T) {
		d := dispatcher.New(service)
		d.HandleBatch(testutil.TestEchoCommand, func(items []execution.Batch) error {
			if err := echoAll(items); err != nil {
				return err
			}
			items[0], items[1] = items[1], items[0]
			items[0].Response = nil
			return nil
		})

		reqs := echoRequests(t, 2)
		resps, err := d.ExecuteAll(reqs)
		require.NoError(t, err)
		requireOK(t, reqs, resps)
	})

	t.Run("completes under WithMaxConcurrency(1)", func(t *testing.T) {
		d := dispatcher.New(service, dispatcher.WithMaxConcurrency(1))
		d.HandleBatch(testutil.TestEchoCommand, echoAll)
		d.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
			return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
		})

		var reqs []execution.Request
		for i := range 10 {
			reqs = append(reqs,
				invoke(t, testutil.TestEchoCommand, datamodel.Map{"i": int64(i)}),
				invoke(t, testutil.ConsoleLogCommand, datamodel.Map{"i": int64(i)}),
			)
		}
		resps, err := d.ExecuteAll(reqs)
		require.NoError(t, err)
		requireOK(t, reqs, resps)
	})

	t.Run("a validated batch runs without waiting for the rest of the request to be admitted", func(t *testing.T) {
		d := dispatcher.New(service, dispatcher.WithMaxConcurrency(1))
		var mu sync.Mutex
		var events []string
		record := func(event string) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, event)
		}
		d.HandleBatch(testutil.TestEchoCommand, func(items []execution.Batch) error {
			record("batch")
			return echoAll(items)
		})
		d.Handle(testutil.ConsoleLogCommand, func(req execution.Request, res execution.Response) error {
			record("single")
			time.Sleep(20 * time.Millisecond)
			return res.SetSuccess(datamodel.Map{})
		})

		reqs := []execution.Request{invoke(t, testutil.TestEchoCommand, datamodel.Map{"i": int64(0)})}
		const singles = 5
		for i := range singles {
			reqs = append(reqs, invoke(t, testutil.ConsoleLogCommand, datamodel.Map{"i": int64(i)}))
		}
		_, err := d.ExecuteAll(reqs)
		require.NoError(t, err)
		// The batch queues for a slot as soon as its validation finishes, so it
		// runs before the last invocations are admitted rather than after.
		require.Less(t, slices.Index(events, "batch"), singles-1, events)
	})

	t.Run("WithMaxConcurrency panics on a negative value", func(t *testing.T) {
		require.Panics(t, func() { dispatcher.WithMaxConcurrency(-1) })
	})
}

func TestDispatcherRejectsNilHandlers(t *testing.T) {
	d := dispatcher.New(testutil.RandomIssuer(t))
	require.PanicsWithValue(t, `dispatcher.Handle: nil handler for "/test/echo"`, func() {
		d.Handle(testutil.TestEchoCommand, nil)
	})
	require.PanicsWithValue(t, `dispatcher.HandleBatch: nil batch handler for "/test/echo"`, func() {
		d.HandleBatch(testutil.TestEchoCommand, nil)
	})
	require.PanicsWithValue(t, "dispatcher.Each: handler must not be nil", func() {
		dispatcher.Each(nil)
	})
}
