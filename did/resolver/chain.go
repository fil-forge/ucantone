package resolver

import (
	"context"
	"errors"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	verrs "github.com/fil-forge/ucantone/validator/errors"
)

// Chain is a DID resolver that tries multiple resolver tiers in order
// until one resolves the DID or all fail. Each tier is expected to return an
// error if it cannot resolve the DID so the next tier can be tried. If all
// tiers fail, the error from each tier is aggregated and returned in a single
// error.
type Chain []did.Resolver

var _ did.Resolver = (Chain)(nil)

func (c Chain) Resolve(ctx context.Context, input did.DID) (did.Document, error) {
	if len(c) == 0 {
		return did.Document{}, verrs.NewDIDKeyResolutionError(input, fmt.Errorf("no resolvers configured"))
	}
	var errs []error
	for _, resolver := range c {
		doc, err := resolver.Resolve(ctx, input)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return doc, nil
	}
	return did.Document{}, verrs.NewDIDKeyResolutionError(input, fmt.Errorf("not resolvable by any resolver: %w", errors.Join(errs...)))
}
