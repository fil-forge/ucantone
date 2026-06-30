//go:build e2e

package plc_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/stretchr/testify/require"
)

// TestE2ELastOperation fetches and decodes the last operation for a known,
// active DID from the live PLC directory. It is gated behind the `e2e` build
// tag and requires network access:
//
//	go test -tags e2e ./did/plc/
func TestE2ELastOperation(t *testing.T) {
	endpoint, err := url.Parse("https://plc.directory")
	require.NoError(t, err)

	c, err := plc.NewDirectoryClient(*endpoint, plc.WithTimeout(30*time.Second))
	require.NoError(t, err)

	d, err := did.Parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	op, err := c.Last(ctx, d)
	require.NoError(t, err)

	require.NotNil(t, op)
	require.Equal(t, plc.OperationType, op.Type)
	require.NotEmpty(t, op.Signature)
	require.NotEmpty(t, op.VerificationMethods)
	require.NotEmpty(t, op.RotationKeys)
}

// TestE2EResolveDocument resolves and parses the DID document for a known,
// active DID from the live PLC directory. It is gated behind the `e2e` build
// tag and requires network access:
//
//	go test -tags e2e ./did/plc/
func TestE2EResolveDocument(t *testing.T) {
	endpoint, err := url.Parse("https://plc.directory")
	require.NoError(t, err)

	r, err := plc.NewResolver(*endpoint, plc.WithTimeout(30*time.Second))
	require.NoError(t, err)

	d, err := did.Parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	doc, err := r.Resolve(ctx, d)
	require.NoError(t, err)

	require.Equal(t, d, doc.ID)
	require.NotNil(t, doc.VerificationMethods)
	require.NotEmpty(t, *doc.VerificationMethods)
	require.NotEmpty(t, doc.Service)
}
