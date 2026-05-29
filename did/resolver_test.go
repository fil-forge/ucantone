package did_test

import (
	"context"
	"errors"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

func TestResolverFunc(t *testing.T) {
	t.Run("calls underlying function", func(t *testing.T) {
		d, err := did.Parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
		require.NoError(t, err)

		want := did.NewDocument(d)
		var resolver did.ResolverFunc = func(_ context.Context, resolved did.DID) (did.Document, error) {
			require.Equal(t, d, resolved)
			return want, nil
		}

		got, err := resolver.Resolve(t.Context(), d)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("propagates error", func(t *testing.T) {
		d, err := did.Parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
		require.NoError(t, err)

		sentinel := errors.New("resolve failed")
		var resolver did.ResolverFunc = func(_ context.Context, _ did.DID) (did.Document, error) {
			return did.Document{}, sentinel
		}

		_, err = resolver.Resolve(t.Context(), d)
		require.ErrorIs(t, err, sentinel)
	})
}

func TestResolverMap(t *testing.T) {
	keyDID, err := did.Parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
	require.NoError(t, err)

	webDID, err := did.Parse("did:web:example.com")
	require.NoError(t, err)

	t.Run("routes to registered method", func(t *testing.T) {
		want := did.NewDocument(keyDID)
		rm := did.ResolverMap{
			"key": did.ResolverFunc(func(_ context.Context, _ did.DID) (did.Document, error) {
				return want, nil
			}),
		}

		got, err := rm.Resolve(t.Context(), keyDID)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("routes to correct method among multiple", func(t *testing.T) {
		keyDoc := did.NewDocument(keyDID)
		webDoc := did.NewDocument(webDID)

		rm := did.ResolverMap{
			"key": did.ResolverFunc(func(_ context.Context, _ did.DID) (did.Document, error) {
				return keyDoc, nil
			}),
			"web": did.ResolverFunc(func(_ context.Context, _ did.DID) (did.Document, error) {
				return webDoc, nil
			}),
		}

		got, err := rm.Resolve(t.Context(), keyDID)
		require.NoError(t, err)
		require.Equal(t, keyDoc, got)

		got, err = rm.Resolve(t.Context(), webDID)
		require.NoError(t, err)
		require.Equal(t, webDoc, got)
	})

	t.Run("returns MethodNotSupportedError for unknown method", func(t *testing.T) {
		rm := did.ResolverMap{}

		_, err := rm.Resolve(t.Context(), keyDID)
		require.Error(t, err)

		var notSupported did.MethodNotSupportedError
		require.ErrorAs(t, err, &notSupported)
		require.Equal(t, "key", notSupported.Method)
	})

	t.Run("MethodNotSupportedError message contains method name", func(t *testing.T) {
		rm := did.ResolverMap{}

		_, err := rm.Resolve(t.Context(), keyDID)
		require.ErrorContains(t, err, "key")
	})
}
