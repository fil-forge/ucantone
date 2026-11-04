package ucanlib_test

import (
	"testing"

	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucanlib"
	"github.com/stretchr/testify/require"
)

func TestContainerProofStore_ProofChain(t *testing.T) {
	t.Run("nil container", func(t *testing.T) {
		ps := ucanlib.NewContainerProofStore(nil)
		space := testutil.RandomIssuer(t)
		alice := testutil.Alice
		cmd := testutil.Must(command.Parse("/test/do"))(t)

		proofs, links, err := ps.ProofChain(t.Context(), alice.DID(), cmd, space.DID())
		require.NoError(t, err)
		require.Empty(t, proofs)
		require.Empty(t, links)
	})

	t.Run("empty container", func(t *testing.T) {
		ps := ucanlib.NewContainerProofStore(container.New())
		space := testutil.RandomIssuer(t)
		alice := testutil.Alice
		cmd := testutil.Must(command.Parse("/test/do"))(t)

		proofs, links, err := ps.ProofChain(t.Context(), alice.DID(), cmd, space.DID())
		require.NoError(t, err)
		require.Empty(t, proofs)
		require.Empty(t, links)
	})

	t.Run("self-issued root", func(t *testing.T) {
		space := testutil.RandomIssuer(t)
		alice := testutil.Alice
		cmd := testutil.Must(command.Parse("/test/do"))(t)

		root := testutil.Must(delegation.Delegate(space, alice.DID(), space.DID(), cmd))(t)

		ct := container.New(container.WithDelegations(root))
		ps := ucanlib.NewContainerProofStore(ct)

		proofs, links, err := ps.ProofChain(t.Context(), alice.DID(), cmd, space.DID())
		require.NoError(t, err)
		assertChain(t, proofs, links, []ucan.Delegation{root})
	})

	t.Run("multi-hop chain", func(t *testing.T) {
		space := testutil.RandomIssuer(t)
		alice := testutil.Alice
		bob := testutil.Bob
		carol := testutil.Carol
		cmd := testutil.Must(command.Parse("/test/do"))(t)

		sa := testutil.Must(delegation.Delegate(space, alice.DID(), space.DID(), cmd))(t)
		ab := testutil.Must(delegation.Delegate(alice, bob.DID(), space.DID(), cmd))(t)
		bc := testutil.Must(delegation.Delegate(bob, carol.DID(), space.DID(), cmd))(t)

		ct := container.New(container.WithDelegations(sa, ab, bc))
		ps := ucanlib.NewContainerProofStore(ct)

		proofs, links, err := ps.ProofChain(t.Context(), carol.DID(), cmd, space.DID())
		require.NoError(t, err)
		assertChain(t, proofs, links, []ucan.Delegation{sa, ab, bc})
	})

	t.Run("parent command resolves via matcher", func(t *testing.T) {
		space := testutil.RandomIssuer(t)
		alice := testutil.Alice
		parent := testutil.Must(command.Parse("/test"))(t)
		child := testutil.Must(command.Parse("/test/do"))(t)

		root := testutil.Must(delegation.Delegate(space, alice.DID(), space.DID(), parent))(t)

		ct := container.New(container.WithDelegations(root))
		ps := ucanlib.NewContainerProofStore(ct)

		proofs, links, err := ps.ProofChain(t.Context(), alice.DID(), child, space.DID())
		require.NoError(t, err)
		assertChain(t, proofs, links, []ucan.Delegation{root})
	})

	t.Run("broken chain returns empty", func(t *testing.T) {
		space := testutil.RandomIssuer(t)
		alice := testutil.Alice
		bob := testutil.Bob
		cmd := testutil.Must(command.Parse("/test/do"))(t)

		// alice → bob exists, but no space → alice root.
		ab := testutil.Must(delegation.Delegate(alice, bob.DID(), space.DID(), cmd))(t)

		ct := container.New(container.WithDelegations(ab))
		ps := ucanlib.NewContainerProofStore(ct)

		proofs, links, err := ps.ProofChain(t.Context(), bob.DID(), cmd, space.DID())
		require.NoError(t, err)
		require.Empty(t, proofs)
		require.Empty(t, links)
	})

	t.Run("filters by audience", func(t *testing.T) {
		space := testutil.RandomIssuer(t)
		alice := testutil.Alice
		bob := testutil.Bob
		cmd := testutil.Must(command.Parse("/test/do"))(t)

		// Delegation to alice, but we ask for bob.
		root := testutil.Must(delegation.Delegate(space, alice.DID(), space.DID(), cmd))(t)

		ct := container.New(container.WithDelegations(root))
		ps := ucanlib.NewContainerProofStore(ct)

		proofs, links, err := ps.ProofChain(t.Context(), bob.DID(), cmd, space.DID())
		require.NoError(t, err)
		require.Empty(t, proofs)
		require.Empty(t, links)
	})

	t.Run("filters by subject", func(t *testing.T) {
		spaceA := testutil.RandomIssuer(t)
		spaceB := testutil.RandomIssuer(t)
		alice := testutil.Alice
		cmd := testutil.Must(command.Parse("/test/do"))(t)

		// Delegation rooted in spaceA, but we ask for spaceB.
		root := testutil.Must(delegation.Delegate(spaceA, alice.DID(), spaceA.DID(), cmd))(t)

		ct := container.New(container.WithDelegations(root))
		ps := ucanlib.NewContainerProofStore(ct)

		proofs, links, err := ps.ProofChain(t.Context(), alice.DID(), cmd, spaceB.DID())
		require.NoError(t, err)
		require.Empty(t, proofs)
		require.Empty(t, links)
	})
}
