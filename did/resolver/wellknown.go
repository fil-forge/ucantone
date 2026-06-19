package resolver

import (
	"context"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	verrs "github.com/fil-forge/ucantone/validator/errors"
)

// WellKnown is a simple resolver that looks up DIDs in a local mapping.
type WellKnown map[did.DID]did.Document

var _ did.Resolver = (WellKnown)(nil)

func (wk WellKnown) Resolve(_ context.Context, input did.DID) (did.Document, error) {
	// ctx is unused; this implementation only looks in a local mapping.
	dk, ok := wk[input]
	if !ok {
		return did.Document{}, verrs.NewDIDKeyResolutionError(input, fmt.Errorf("not found in mapping: %s", input))
	}
	return dk, nil
}
