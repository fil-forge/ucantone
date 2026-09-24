package ucanlib

import (
	"context"
	"iter"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

type ProofStore interface {
	// ProofChain recursively builds a proof chain of delegations from the given
	// audience to the given subject for the specified command. It returns the
	// list of delegations and their corresponding links in the order required for
	// invocation. i.e. starting from the root Delegation (issued by the Subject),
	// in strict sequence where the aud of the previous Delegation matches the iss
	// of the next Delegation.
	ProofChain(ctx context.Context, aud did.DID, cmd ucan.Command, sub did.DID) ([]ucan.Delegation, []cid.Cid, error)
}

// ContainerProofStore is a proof store backed by an in-memory container.
type ContainerProofStore struct {
	container ucan.Container
}

// NewContainerProofStore creates a proof store backed by an in-memory container.
func NewContainerProofStore(ct ucan.Container) *ContainerProofStore {
	return &ContainerProofStore{container: ct}
}

func (cps *ContainerProofStore) ProofChain(ctx context.Context, aud did.DID, cmd ucan.Command, sub did.DID) ([]ucan.Delegation, []cid.Cid, error) {
	return ProofChain(ctx, cps.matchDelegations, aud, cmd, sub)
}

func (ps *ContainerProofStore) listDelegations(ctx context.Context, aud did.DID, cmd ucan.Command, sub did.DID) iter.Seq2[ucan.Delegation, error] {
	return func(yield func(ucan.Delegation, error) bool) {
		if ps.container == nil {
			return
		}
		for _, d := range ps.container.Delegations() {
			if d.Audience() == aud && d.Command() == cmd && d.Subject() == sub {
				if !yield(d, nil) {
					return
				}
			}
		}
	}
}

func (ps *ContainerProofStore) matchDelegations(ctx context.Context, aud did.DID, cmd ucan.Command, sub did.DID) iter.Seq2[ucan.Delegation, error] {
	return NewDelegationMatcher(ps.listDelegations)(ctx, aud, cmd, sub)
}
