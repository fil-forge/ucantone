package execution_test

import (
	"testing"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/ucan/receipt"
	"github.com/stretchr/testify/require"
)

func TestNewRequest(t *testing.T) {
	alice := testutil.RandomIssuer(t)
	service := testutil.RandomIssuer(t)

	inv, err := invocation.Invoke(alice, alice.DID(), testutil.TestEchoCommand, datamodel.Map{}, invocation.WithAudience(service.DID()))
	require.NoError(t, err)
	dlg, err := delegation.Delegate(service, alice.DID(), service.DID(), testutil.TestEchoCommand)
	require.NoError(t, err)
	cause, err := invocation.Invoke(alice, alice.DID(), testutil.ConsoleLogCommand, datamodel.Map{})
	require.NoError(t, err)
	rcpt, err := receipt.IssueOK(service, cause.Task().Link(), datamodel.Map{})
	require.NoError(t, err)

	t.Run("no metadata without options", func(t *testing.T) {
		req := execution.NewRequest(t.Context(), inv)
		require.Nil(t, req.Metadata())
	})

	t.Run("token options build the metadata container", func(t *testing.T) {
		req := execution.NewRequest(t.Context(), inv,
			execution.WithDelegations(dlg),
			execution.WithInvocations(cause),
			execution.WithReceipts(rcpt),
		)
		require.Equal(t, []ucan.Delegation{dlg}, req.Metadata().Delegations())
		require.Equal(t, []ucan.Invocation{cause}, req.Metadata().Invocations())
		require.Equal(t, []ucan.Receipt{rcpt}, req.Metadata().Receipts())
	})

	t.Run("WithRequestMetadata sets the container as is", func(t *testing.T) {
		meta := container.New(container.WithDelegations(dlg))
		req := execution.NewRequest(t.Context(), inv, execution.WithRequestMetadata(meta))
		require.Same(t, meta, req.Metadata())
	})

	t.Run("WithRequestMetadata(nil) leaves the metadata nil", func(t *testing.T) {
		req := execution.NewRequest(t.Context(), inv, execution.WithRequestMetadata(nil))
		require.Nil(t, req.Metadata())
	})

	t.Run("merged with token options", func(t *testing.T) {
		// A second token of every kind, so the container and the options each
		// contribute one and the order of the merge is observable.
		metaDlg, err := delegation.Delegate(alice, service.DID(), alice.DID(), testutil.ConsoleLogCommand)
		require.NoError(t, err)
		metaInv, err := invocation.Invoke(service, service.DID(), testutil.ConsoleLogCommand, datamodel.Map{})
		require.NoError(t, err)
		metaRcpt, err := receipt.IssueOK(alice, metaInv.Task().Link(), datamodel.Map{})
		require.NoError(t, err)
		meta := container.New(
			container.WithInvocations(metaInv),
			container.WithDelegations(metaDlg),
			container.WithReceipts(metaRcpt),
		)
		merged := func(options ...execution.RequestOption) ucan.Container {
			options = append([]execution.RequestOption{execution.WithRequestMetadata(meta)}, options...)
			return execution.NewRequest(t.Context(), inv, options...).Metadata()
		}

		t.Run("container invocations come before WithInvocations", func(t *testing.T) {
			require.Equal(t, []ucan.Invocation{metaInv, cause}, merged(execution.WithInvocations(cause)).Invocations())
		})

		t.Run("container delegations come before WithDelegations", func(t *testing.T) {
			require.Equal(t, []ucan.Delegation{metaDlg, dlg}, merged(execution.WithDelegations(dlg)).Delegations())
		})

		t.Run("container receipts come before WithReceipts", func(t *testing.T) {
			require.Equal(t, []ucan.Receipt{metaRcpt, rcpt}, merged(execution.WithReceipts(rcpt)).Receipts())
		})

		t.Run("a token present in both appears once, in the container's position", func(t *testing.T) {
			require.Equal(t, []ucan.Delegation{metaDlg, dlg}, merged(execution.WithDelegations(dlg, metaDlg)).Delegations())
		})

		t.Run("Delegation(cid) finds tokens from both sources", func(t *testing.T) {
			ct := merged(execution.WithDelegations(dlg))
			fromMeta, okMeta := ct.Delegation(metaDlg.Link())
			fromOption, okOption := ct.Delegation(dlg.Link())
			require.Equal(t,
				[]any{metaDlg, true, dlg, true},
				[]any{fromMeta, okMeta, fromOption, okOption},
			)
		})

		t.Run("Receipt(cid) finds tokens from both sources", func(t *testing.T) {
			ct := merged(execution.WithReceipts(rcpt))
			fromMeta, okMeta := ct.Receipt(metaRcpt.Ran())
			fromOption, okOption := ct.Receipt(rcpt.Ran())
			require.Equal(t,
				[]any{metaRcpt, true, rcpt, true},
				[]any{fromMeta, okMeta, fromOption, okOption},
			)
		})

		t.Run("the merged container is a new instance", func(t *testing.T) {
			require.NotSame(t, meta, merged(execution.WithDelegations(dlg)))
		})
	})

	t.Run("WithRequestMetadata(nil) with token options equals the options alone", func(t *testing.T) {
		withNil := execution.NewRequest(t.Context(), inv, execution.WithRequestMetadata(nil), execution.WithDelegations(dlg))
		alone := execution.NewRequest(t.Context(), inv, execution.WithDelegations(dlg))
		require.Equal(t, alone.Metadata(), withNil.Metadata())
	})
}
