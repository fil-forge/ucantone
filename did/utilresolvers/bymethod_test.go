package utilresolvers_test

import (
	"context"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/utilresolvers"
	"github.com/stretchr/testify/require"
)

func TestByMethod(t *testing.T) {
	did1, err := did.Parse("did:web:example.com")
	require.NoError(t, err)
	did2, err := did.Parse("did:key:z6MkghfetkhrBZwUupJrv8MmYDH1JhKCQCGj1trbaZPA3dAd")
	require.NoError(t, err)
	did3, err := did.Parse("did:example:abc123")
	require.NoError(t, err)

	var expectDID = func(expected did.DID) did.ResolverFunc {
		return func(_ context.Context, input did.DID) (did.Document, error) {
			require.Equal(t, expected, input)
			return did.NewDocument(input), nil
		}
	}

	resolver := utilresolvers.ByMethod{
		"web":     expectDID(did1),
		"key":     expectDID(did2),
		"example": expectDID(did3),
	}

	doc, err := resolver.Resolve(nil, did1)
	require.NoError(t, err)
	require.Equal(t, did1, doc.ID)

	doc, err = resolver.Resolve(nil, did2)
	require.NoError(t, err)
	require.Equal(t, did2, doc.ID)

	doc, err = resolver.Resolve(nil, did3)
	require.NoError(t, err)
	require.Equal(t, did3, doc.ID)

	_, err = resolver.Resolve(nil, did.MustParse("did:unknown:abc123"))
	require.Error(t, err)
}
