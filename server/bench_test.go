package server_test

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
)

// BenchmarkBatch compares one request carrying n invocations against n
// concurrent requests carrying one each, for a handler that waits on I/O
// (modelled as a 1ms sleep) and one that burns CPU (hashing 256 KiB). The
// sequential variant caps the request at one invocation at a time, which is
// how every request executed before the invocations of a request ran
// concurrently.
func BenchmarkBatch(b *testing.B) {
	const n = 100
	service, err := ed25519.GenerateIssuer()
	if err != nil {
		b.Fatal(err)
	}
	alice, err := ed25519.GenerateIssuer()
	if err != nil {
		b.Fatal(err)
	}

	invs := make([]ucan.Invocation, 0, n)
	for i := range n {
		inv, err := invocation.Invoke(alice, alice.DID(), testutil.TestEchoCommand, datamodel.Map{"i": int64(i)}, invocation.WithAudience(service.DID()))
		if err != nil {
			b.Fatal(err)
		}
		invs = append(invs, inv)
	}

	payload := make([]byte, 256<<10)
	handlers := []struct {
		name    string
		handler execution.HandlerFunc
	}{
		{"io", func(req execution.Request, res execution.Response) error {
			time.Sleep(time.Millisecond)
			return res.SetSuccess(datamodel.Map{})
		}},
		{"cpu", func(req execution.Request, res execution.Response) error {
			sum := sha256.Sum256(payload)
			return res.SetSuccess(datamodel.Map{"sum": sum[:]})
		}},
	}

	for _, h := range handlers {
		name, handler := h.name, h.handler
		srv := server.NewHTTP(service)
		srv.Handle(testutil.TestEchoCommand, handler)

		// A cap of one is how every request executed before invocations ran
		// concurrently.
		sequential := server.NewHTTP(service, server.WithMaxConcurrency(1))
		sequential.Handle(testutil.TestEchoCommand, handler)

		b.Run(fmt.Sprintf("%s/1x%d/sequential", name, n), func(b *testing.B) {
			for b.Loop() {
				if _, err := sequential.ExecuteBatch(batch.NewRequest(b.Context(), invs)); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("%s/1x%d", name, n), func(b *testing.B) {
			for b.Loop() {
				if _, err := srv.ExecuteBatch(batch.NewRequest(b.Context(), invs)); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("%s/%dx1", name, n), func(b *testing.B) {
			for b.Loop() {
				var wg sync.WaitGroup
				for _, inv := range invs {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if _, err := srv.ExecuteBatch(batch.NewRequest(b.Context(), []ucan.Invocation{inv})); err != nil {
							b.Error(err)
						}
					}()
				}
				wg.Wait()
			}
		})
	}
}
