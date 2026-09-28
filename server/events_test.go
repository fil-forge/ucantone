package server_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

// listenerFuncs is an [server.EventListener] built from two functions; a nil
// function is a no-op.
type listenerFuncs struct {
	decode func(ctx context.Context, ct ucan.Container) error
	encode func(ctx context.Context, ct ucan.Container) error
}

func (l listenerFuncs) OnRequestDecode(ctx context.Context, ct ucan.Container) error {
	if l.decode == nil {
		return nil
	}
	return l.decode(ctx, ct)
}

func (l listenerFuncs) OnResponseEncode(ctx context.Context, ct ucan.Container) error {
	if l.encode == nil {
		return nil
	}
	return l.encode(ctx, ct)
}

// roundTrip sends one echo invocation through the server and returns the
// response container, or the error RoundTrip reported.
func roundTrip(t *testing.T, srv *server.HTTPServer, alice, service ucan.Issuer) (*container.Container, error) {
	t.Helper()
	inv, err := invocation.Invoke(alice, alice.DID(), testutil.TestEchoCommand, datamodel.Map{}, invocation.WithAudience(service.DID()))
	require.NoError(t, err)
	ct := container.New(container.WithInvocations(inv))

	r, w := io.Pipe()
	go func() {
		w.CloseWithError(ct.MarshalCBOR(w))
	}()
	req := (&http.Request{Header: http.Header{}, Body: r}).WithContext(t.Context())
	req.Header.Set("Content-Type", dagcbor.ContentType)

	resp, err := srv.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	var ctResp container.Container
	require.NoError(t, ctResp.UnmarshalCBOR(resp.Body))
	return &ctResp, nil
}

// awaitOr waits for ch to close, or fails with msg after a while.
func awaitOr(ch <-chan struct{}, msg string) error {
	select {
	case <-ch:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New(msg)
	}
}

func TestHTTPServerConcurrentEventListener(t *testing.T) {
	service := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)

	t.Run("runs while the handlers execute", func(t *testing.T) {
		// The listener and the handler each wait for the other to have
		// started, which only completes when they run at the same time.
		listenerIn := make(chan struct{})
		handlerIn := make(chan struct{})
		srv := server.NewHTTP(service, server.WithConcurrentEventListener(listenerFuncs{
			decode: func(ctx context.Context, ct ucan.Container) error {
				close(listenerIn)
				return awaitOr(handlerIn, "listener timed out waiting for the handler")
			},
		}))
		srv.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			close(handlerIn)
			if err := awaitOr(listenerIn, "handler timed out waiting for the listener"); err != nil {
				return err
			}
			return res.SetSuccess(datamodel.Map{})
		})

		ct, err := roundTrip(t, srv, alice, service)
		require.NoError(t, err)
		require.Len(t, ct.Receipts(), 1)
		_, x := ct.Receipts()[0].Out().Unpack()
		require.Nil(t, x)
	})

	t.Run("finishes before the response listeners run", func(t *testing.T) {
		// The listener outlives the handler on purpose, so a server that did
		// not wait for it would run a response listener first. Its own
		// OnResponseEncode runs too, in registration order with the rest.
		handlerDone := make(chan struct{})
		var mu sync.Mutex
		var order []string
		record := func(event string) {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, event)
		}
		srv := server.NewHTTP(service,
			server.WithConcurrentEventListener(listenerFuncs{
				decode: func(ctx context.Context, ct ucan.Container) error {
					if err := awaitOr(handlerDone, "listener timed out waiting for the handler"); err != nil {
						return err
					}
					time.Sleep(20 * time.Millisecond)
					record("request decoded")
					return nil
				},
				encode: func(ctx context.Context, ct ucan.Container) error {
					record("response encoded")
					return nil
				},
			}),
			server.WithEventListener(listenerFuncs{
				encode: func(ctx context.Context, ct ucan.Container) error {
					record("response encoded, synchronous listener")
					return nil
				},
			}),
		)
		srv.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			close(handlerDone)
			return res.SetSuccess(datamodel.Map{})
		})

		_, err := roundTrip(t, srv, alice, service)
		require.NoError(t, err)
		require.Equal(t, []string{"request decoded", "response encoded", "response encoded, synchronous listener"}, order)
	})

	t.Run("an error fails the request after the handlers ran", func(t *testing.T) {
		listenerErr := errors.New("store unavailable")
		srv := server.NewHTTP(service, server.WithConcurrentEventListener(listenerFuncs{
			decode: func(ctx context.Context, ct ucan.Container) error { return listenerErr },
		}))
		handled := false
		srv.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			handled = true
			return res.SetSuccess(datamodel.Map{})
		})

		_, err := roundTrip(t, srv, alice, service)
		require.ErrorIs(t, err, listenerErr)
		require.True(t, handled)
	})

	t.Run("a panic fails the request", func(t *testing.T) {
		srv := server.NewHTTP(service, server.WithConcurrentEventListener(listenerFuncs{
			decode: func(ctx context.Context, ct ucan.Container) error { panic("boom") },
		}))
		srv.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			return res.SetSuccess(datamodel.Map{})
		})

		_, err := roundTrip(t, srv, alice, service)
		require.ErrorContains(t, err, "listener panicked: boom")
	})

	t.Run("a synchronous listener still runs before the handlers", func(t *testing.T) {
		gateErr := errors.New("rejected")
		srv := server.NewHTTP(service, server.WithEventListener(listenerFuncs{
			decode: func(ctx context.Context, ct ucan.Container) error { return gateErr },
		}))
		handled := false
		srv.Handle(testutil.TestEchoCommand, func(req execution.Request, res execution.Response) error {
			handled = true
			return res.SetSuccess(datamodel.Map{})
		})

		_, err := roundTrip(t, srv, alice, service)
		require.ErrorIs(t, err, gateErr)
		require.False(t, handled)
	})
}
