package resolver_test

import (
	"context"
	"errors"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/resolver"
	"github.com/stretchr/testify/require"
)

func TestTiered(t *testing.T) {
	resolvedDID, err := did.Parse("did:example:abc123")
	require.NoError(t, err)

	t.Run("returns from the first resolver when it succeeds", func(t *testing.T) {
		tieredResolver := &resolver.Tiered{
			did.ResolverFunc(func(ctx context.Context, input did.DID) (did.Document, error) {
				return did.NewDocument(resolvedDID), nil
			}),
			did.ResolverFunc(func(ctx context.Context, input did.DID) (did.Document, error) {
				require.Fail(t, "second resolver should not be called when first resolver succeeds")
				return did.Document{}, nil
			}),
		}

		result, err := tieredResolver.Resolve(t.Context(), resolvedDID)
		require.NoError(t, err)
		require.Equal(t, did.NewDocument(resolvedDID), result)
	})

	t.Run("falls through to later resolver when earlier resolvers fail", func(t *testing.T) {
		tieredResolver := &resolver.Tiered{
			did.ResolverFunc(func(ctx context.Context, input did.DID) (did.Document, error) {
				return did.Document{}, errors.New("first resolver failed")
			}),
			did.ResolverFunc(func(ctx context.Context, input did.DID) (did.Document, error) {
				return did.Document{}, errors.New("second resolver failed")
			}),
			did.ResolverFunc(func(ctx context.Context, input did.DID) (did.Document, error) {
				return did.NewDocument(resolvedDID), nil
			}),
		}

		result, err := tieredResolver.Resolve(t.Context(), resolvedDID)
		require.NoError(t, err)
		require.Equal(t, did.NewDocument(resolvedDID), result)
	})

	t.Run("returns joined error when all tiers fail", func(t *testing.T) {
		tieredResolver := &resolver.Tiered{
			did.ResolverFunc(func(ctx context.Context, input did.DID) (did.Document, error) {
				return did.Document{}, errors.New("first resolver failed")
			}),
			did.ResolverFunc(func(ctx context.Context, input did.DID) (did.Document, error) {
				return did.Document{}, errors.New("second resolver failed")
			}),
			did.ResolverFunc(func(ctx context.Context, input did.DID) (did.Document, error) {
				return did.Document{}, errors.New("third resolver failed")
			}),
		}

		_, err := tieredResolver.Resolve(t.Context(), resolvedDID)

		var joinedError interface{ Unwrap() []error }
		require.ErrorAs(t, err, &joinedError)

		require.Contains(t, err.Error(), "not resolvable by any resolver")
		unwrappedErrors := joinedError.Unwrap()
		require.Len(t, unwrappedErrors, 3)
		require.Contains(t, unwrappedErrors[0].Error(), "first resolver failed")
		require.Contains(t, unwrappedErrors[1].Error(), "second resolver failed")
		require.Contains(t, unwrappedErrors[2].Error(), "third resolver failed")
	})

	t.Run("returns error with no tiers configured", func(t *testing.T) {
		tieredResolver := &resolver.Tiered{
			// No resolvers configured
		}
		_, err := tieredResolver.Resolve(t.Context(), resolvedDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to resolve")
		require.Contains(t, err.Error(), "no resolvers configured")
	})
}
