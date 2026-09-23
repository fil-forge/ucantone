package server_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

// barrierHandler blocks every invocation until n of them have entered, so a
// batch of n completes only when they all run at the same time. Under
// sequential execution or a cap below n the first one times out instead.
func barrierHandler(n int) execution.HandlerFunc {
	var entered atomic.Int32
	release := make(chan struct{})
	return func(req execution.Request, res execution.Response) error {
		if entered.Add(1) == int32(n) {
			close(release)
		}
		select {
		case <-release:
			return res.SetSuccess(datamodel.Map{})
		case <-time.After(5 * time.Second):
			return fmt.Errorf("timed out waiting for %d concurrent invocations", n)
		}
	}
}

func echoBatch(t *testing.T, alice, service ucan.Issuer, n int) []ucan.Invocation {
	invs := make([]ucan.Invocation, 0, n)
	for i := range n {
		inv, err := invocation.Invoke(alice, alice.DID(), testutil.TestEchoCommand, datamodel.Map{"i": int64(i)}, invocation.WithAudience(service.DID()))
		require.NoError(t, err)
		invs = append(invs, inv)
	}
	return invs
}

func requireAllOK(t *testing.T, res *batch.Response, invs []ucan.Invocation) {
	failures := map[string]any{}
	for _, inv := range invs {
		rcpt, ok := res.Receipt(inv.Task().Link())
		require.True(t, ok, "missing receipt for %s", inv.Task().Link())
		if _, x := rcpt.Out().Unpack(); x != nil {
			failures[inv.Task().Link().String()] = testutil.ResultMap(t, x)["message"]
		}
	}
	require.Empty(t, failures)
}

func TestHTTPServerConcurrency(t *testing.T) {
	service := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)

	t.Run("invocations of one request execute concurrently", func(t *testing.T) {
		const n = 10
		srv := server.NewHTTP(service)
		srv.Handle(testutil.TestEchoCommand, barrierHandler(n))
		invs := echoBatch(t, alice, service, n)

		res, err := srv.ExecuteBatch(batch.NewRequest(t.Context(), invs))
		require.NoError(t, err)
		requireAllOK(t, res, invs)
	})

	t.Run("WithMaxConcurrency(0) removes the cap", func(t *testing.T) {
		n := server.DefaultMaxConcurrency + 50
		srv := server.NewHTTP(service, server.WithMaxConcurrency(0))
		srv.Handle(testutil.TestEchoCommand, barrierHandler(n))
		invs := echoBatch(t, alice, service, n)

		res, err := srv.ExecuteBatch(batch.NewRequest(t.Context(), invs))
		require.NoError(t, err)
		requireAllOK(t, res, invs)
	})

	t.Run("WithMaxConcurrency caps how many run at once", func(t *testing.T) {
		const cap, n = 2, 5
		srv := server.NewHTTP(service, server.WithMaxConcurrency(cap))

		// Each handler waits until cap invocations are in flight before it
		// finishes, so the peak reaches cap by construction, and the
		// semaphore keeps it from going past.
		var inFlight, peak atomic.Int32
		full := make(chan struct{})
		var closeFull sync.Once
		srv.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			now := inFlight.Add(1)
			defer inFlight.Add(-1)
			for {
				seen := peak.Load()
				if now <= seen || peak.CompareAndSwap(seen, now) {
					break
				}
			}
			if now == cap {
				closeFull.Do(func() { close(full) })
			}
			select {
			case <-full:
				return res.SetSuccess(datamodel.Map{})
			case <-time.After(5 * time.Second):
				return fmt.Errorf("timed out waiting for %d in-flight invocations", cap)
			}
		})
		invs := echoBatch(t, alice, service, n)

		res, err := srv.ExecuteBatch(batch.NewRequest(t.Context(), invs))
		require.NoError(t, err)
		requireAllOK(t, res, invs)
		require.Equal(t, int32(cap), peak.Load())
	})

	t.Run("WithMaxConcurrency panics on a negative value", func(t *testing.T) {
		require.PanicsWithValue(t, "server.WithMaxConcurrency: n must not be negative", func() {
			server.WithMaxConcurrency(-1)
		})
	})

	t.Run("response metadata stays in request order", func(t *testing.T) {
		const n = 20
		srv := server.NewHTTP(service)
		// Later invocations finish first, so metadata gathered in completion
		// order would come back reversed.
		srv.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			i := testutil.ArgsMap(t, req.Invocation())["i"].(int64)
			time.Sleep(time.Duration(n-i) * time.Millisecond)
			claim, err := invocation.Invoke(service, service.DID(), testutil.ConsoleLogCommand, datamodel.Map{"i": i})
			if err != nil {
				return err
			}
			if err := res.SetMetadata(container.New(container.WithInvocations(claim))); err != nil {
				return err
			}
			return res.SetSuccess(datamodel.Map{})
		})
		invs := echoBatch(t, alice, service, n)

		res, err := srv.ExecuteBatch(batch.NewRequest(t.Context(), invs))
		require.NoError(t, err)
		requireAllOK(t, res, invs)

		require.NotNil(t, res.Metadata())
		var got []int64
		for _, claim := range res.Metadata().Invocations() {
			got = append(got, testutil.ArgsMap(t, claim)["i"].(int64))
		}
		want := make([]int64, n)
		for i := range want {
			want[i] = int64(i)
		}
		require.Equal(t, want, got)
	})
}
