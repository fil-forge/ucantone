package did

import (
	"context"
)

// Resolver resolves a DID to a DID Document.
type Resolver interface {
	Resolve(ctx context.Context, d DID) (Document, error)
}

// ResolverFunc is a simple function [Resolver].
type ResolverFunc func(ctx context.Context, d DID) (Document, error)

func (f ResolverFunc) Resolve(ctx context.Context, d DID) (Document, error) {
	return f(ctx, d)
}

type ResolverMap map[string]Resolver

func (rm ResolverMap) Resolve(ctx context.Context, d DID) (Document, error) {
	method := d.Method()
	resolver, ok := rm[method]
	if !ok {
		return Document{}, MethodNotSupportedError{Method: method}
	}
	return resolver.Resolve(ctx, d)
}

type MethodNotSupportedError struct {
	Method string
}

func (e MethodNotSupportedError) Error() string {
	return "DID method not supported: " + e.Method
}
