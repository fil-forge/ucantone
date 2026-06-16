package resolver_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/resolver"
	"github.com/stretchr/testify/require"
)

func TestCached(t *testing.T) {
	exampleDID, err := did.Parse("did:example:abc123")
	require.NoError(t, err)

	t.Run("caches successful resolution", func(t *testing.T) {
		var calls int
		resolver := resolver.NewCached(did.ResolverFunc(func(ctx context.Context, d did.DID) (did.Document, error) {
			calls++
			return did.NewDocument(d), nil
		}), 100*time.Millisecond)

		result1, err := resolver.Resolve(t.Context(), exampleDID)
		require.NoError(t, err)
		require.Equal(t, did.NewDocument(exampleDID), result1)
		require.Equal(t, 1, calls)

		result2, err := resolver.Resolve(t.Context(), exampleDID)
		require.NoError(t, err)
		require.Equal(t, did.NewDocument(exampleDID), result2)
		require.Equal(t, 1, calls)

		time.Sleep(150 * time.Millisecond)

		result3, err := resolver.Resolve(t.Context(), exampleDID)
		require.NoError(t, err)
		require.Equal(t, did.NewDocument(exampleDID), result3)
		require.Equal(t, 2, calls)
	})

	t.Run("does not cache errors", func(t *testing.T) {
		var calls int
		resolver := resolver.NewCached(did.ResolverFunc(func(ctx context.Context, d did.DID) (did.Document, error) {
			calls++
			return did.Document{}, errors.New("resolution failed")
		}), 100*time.Millisecond)

		_, err = resolver.Resolve(t.Context(), exampleDID)
		require.Error(t, err)
		require.Equal(t, 1, calls)

		_, err = resolver.Resolve(t.Context(), exampleDID)
		require.Error(t, err)
		require.Equal(t, 2, calls)
	})

	t.Run("handles concurrent access", func(t *testing.T) {
		var calls atomic.Int32
		resolver := resolver.NewCached(did.ResolverFunc(func(ctx context.Context, d did.DID) (did.Document, error) {
			calls.Add(1)
			time.Sleep(10 * time.Millisecond)
			return did.NewDocument(d), nil
		}), time.Second)

		var wg sync.WaitGroup
		results := make([]did.Document, 10)
		errs := make([]error, 10)
		for i := range 10 {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx], errs[idx] = resolver.Resolve(t.Context(), exampleDID)
			}(i)
		}
		wg.Wait()

		for i := range 10 {
			require.NoError(t, errs[i])
			require.Equal(t, did.NewDocument(exampleDID), results[i])
		}

		callsAfterWait := calls.Load()

		// Cache hit — no additional call.
		_, err = resolver.Resolve(t.Context(), exampleDID)
		require.NoError(t, err)
		require.Equal(t, callsAfterWait, calls.Load())
	})

	t.Run("handles different DIDs independently", func(t *testing.T) {
		did1, err := did.Parse("did:example:one")
		require.NoError(t, err)
		did2, err := did.Parse("did:example:two")
		require.NoError(t, err)

		var calls int
		resolver := resolver.NewCached(did.ResolverFunc(func(ctx context.Context, d did.DID) (did.Document, error) {
			calls++
			return did.NewDocument(d), nil
		}), time.Second)

		result1, err := resolver.Resolve(t.Context(), did1)
		require.NoError(t, err)
		require.Equal(t, did.NewDocument(did1), result1)
		require.Equal(t, 1, calls)

		result2, err := resolver.Resolve(t.Context(), did2)
		require.NoError(t, err)
		require.Equal(t, did.NewDocument(did2), result2)
		require.Equal(t, 2, calls)

		result3, err := resolver.Resolve(t.Context(), did1)
		require.NoError(t, err)
		require.Equal(t, did.NewDocument(did1), result3)
		require.Equal(t, 2, calls)

		result4, err := resolver.Resolve(t.Context(), did2)
		require.NoError(t, err)
		require.Equal(t, did.NewDocument(did2), result4)
		require.Equal(t, 2, calls)
	})
}
