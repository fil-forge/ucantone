package utilresolvers

import (
	"context"
	"fmt"

	"github.com/fil-forge/ucantone/did"
)

type ByMethod map[string]did.Resolver

func (bm ByMethod) Resolve(ctx context.Context, input did.DID) (did.Document, error) {
	resolver, ok := bm[input.Method()]
	if !ok {
		return did.Document{}, fmt.Errorf("no resolver found for method: %s", input.Method())
	}

	return resolver.Resolve(ctx, input)
}
