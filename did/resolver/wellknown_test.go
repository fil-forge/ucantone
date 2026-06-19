package resolver_test

import (
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/resolver"
	"github.com/stretchr/testify/require"
)

func TestWellKnown(t *testing.T) {
	did1, err := did.Parse("did:web:example.com")
	require.NoError(t, err)
	did2, err := did.Parse("did:key:z6MkghfetkhrBZwUupJrv8MmYDH1JhKCQCGj1trbaZPA3dAd")
	require.NoError(t, err)
	did3, err := did.Parse("did:web:example.org")
	require.NoError(t, err)

	wellKnownResolver := resolver.WellKnown{
		did1: did.NewDocument(did1),
		did2: did.NewDocument(did2),
		did3: did.NewDocument(did3),
	}

	result, err := wellKnownResolver.Resolve(t.Context(), did1)
	require.NoError(t, err)
	require.Equal(t, did1, result.ID)

	result, err = wellKnownResolver.Resolve(t.Context(), did2)
	require.NoError(t, err)
	require.Equal(t, did2, result.ID)

	result, err = wellKnownResolver.Resolve(t.Context(), did3)
	require.NoError(t, err)
	require.Equal(t, did3, result.ID)
}
