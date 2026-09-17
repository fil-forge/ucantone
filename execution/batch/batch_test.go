package batch_test

import (
	"testing"

	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/ucan/receipt"
	"github.com/stretchr/testify/require"
)

func TestRequest(t *testing.T) {
	alice := testutil.RandomIssuer(t)
	service := testutil.RandomIssuer(t)

	inv, err := invocation.Invoke(alice, alice.DID(), testutil.TestEchoCommand, datamodel.Map{}, invocation.WithAudience(service.DID()))
	require.NoError(t, err)

	t.Run("no metadata without options", func(t *testing.T) {
		req := batch.NewRequest(t.Context(), []ucan.Invocation{inv})
		require.Equal(t, []ucan.Invocation{inv}, req.Invocations())
		require.Nil(t, req.Metadata())
	})

	t.Run("options build the metadata container", func(t *testing.T) {
		dlg, err := delegation.Delegate(service, alice.DID(), service.DID(), testutil.TestEchoCommand)
		require.NoError(t, err)
		cause, err := invocation.Invoke(alice, alice.DID(), testutil.ConsoleLogCommand, datamodel.Map{})
		require.NoError(t, err)
		rcpt, err := receipt.IssueOK(service, cause.Task().Link(), datamodel.Map{})
		require.NoError(t, err)

		req := batch.NewRequest(t.Context(), []ucan.Invocation{inv},
			batch.WithDelegations(dlg),
			batch.WithInvocations(cause),
			batch.WithReceipts(rcpt),
		)
		require.Equal(t, []ucan.Invocation{inv}, req.Invocations())
		require.Equal(t, []ucan.Delegation{dlg}, req.Metadata().Delegations())
		require.Equal(t, []ucan.Invocation{cause}, req.Metadata().Invocations())
		require.Equal(t, []ucan.Receipt{rcpt}, req.Metadata().Receipts())
	})
}

func TestResponse(t *testing.T) {
	alice := testutil.RandomIssuer(t)
	service := testutil.RandomIssuer(t)

	var rcpts []ucan.Receipt
	for range 3 {
		inv, err := invocation.Invoke(alice, alice.DID(), testutil.TestEchoCommand, datamodel.Map{})
		require.NoError(t, err)
		rcpt, err := receipt.IssueOK(service, inv.Task().Link(), datamodel.Map{})
		require.NoError(t, err)
		rcpts = append(rcpts, rcpt)
	}

	t.Run("receipt lookup by task", func(t *testing.T) {
		res := batch.NewResponse(rcpts)
		require.Nil(t, res.Metadata())
		for _, want := range rcpts {
			got, ok := res.Receipt(want.Ran())
			require.True(t, ok)
			require.Equal(t, want, got)
		}
		_, ok := res.Receipt(testutil.RandomCID(t))
		require.False(t, ok)
	})

	t.Run("metadata", func(t *testing.T) {
		meta := container.New(container.WithReceipts(rcpts[0]))
		res := batch.NewResponse(rcpts[1:], batch.WithMetadata(meta))
		require.Equal(t, meta, res.Metadata())
	})
}
