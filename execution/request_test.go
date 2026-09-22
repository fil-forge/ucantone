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

	t.Run("WithMetadataContainer sets the container as is", func(t *testing.T) {
		meta := container.New(container.WithDelegations(dlg))
		req := execution.NewRequest(t.Context(), inv, execution.WithMetadataContainer(meta))
		require.Same(t, meta, req.Metadata())
	})

	t.Run("WithMetadataContainer(nil) leaves the metadata nil", func(t *testing.T) {
		req := execution.NewRequest(t.Context(), inv, execution.WithMetadataContainer(nil))
		require.Nil(t, req.Metadata())
	})

	conflicting := map[string]execution.RequestOption{
		"WithInvocations": execution.WithInvocations(cause),
		"WithDelegations": execution.WithDelegations(dlg),
		"WithReceipts":    execution.WithReceipts(rcpt),
	}
	containers := map[string]ucan.Container{
		"a container": container.New(container.WithDelegations(dlg)),
		"nil":         nil,
	}
	for optName, opt := range conflicting {
		for metaName, meta := range containers {
			t.Run("panics when WithMetadataContainer("+metaName+") is combined with "+optName, func(t *testing.T) {
				require.PanicsWithValue(t,
					"execution.NewRequest: WithMetadataContainer cannot be combined with WithInvocations, WithDelegations or WithReceipts",
					func() { execution.NewRequest(t.Context(), inv, execution.WithMetadataContainer(meta), opt) },
				)
			})
		}
	}
}
