// Package middleware holds authorization checks a server's routes can be served
// behind. Each wraps a [server.Route]'s handler, so it runs after the
// invocations have been validated and before the command sees them, and
// records a rejection as that invocation's receipt failure. The handler
// receives only the invocations every check accepted.
//
// The checks are about who an invocation came from and what it claims authority
// over, which validation alone does not settle: a valid invocation may still be
// one the service will not act on. A service serving commands for others applies
// [NotSelfSigned] and [OnlySubject]; one serving a command it invokes on itself
// applies [OnlyIssuer], which [NotSelfSigned] would reject.
//
// They are silent. A service that wants a record of the rejections adds a
// middleware of its own, outermost, that inspects the receipts the chain
// produced once its handler returns; it is handed the route, so it can bind the command to its logger
// once instead of reading it back off every invocation.
package middleware

import (
	"github.com/fil-forge/ucantone/did"
	ucanerrors "github.com/fil-forge/ucantone/errors"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server"
)

// Error names for the rejections, exported so callers can match on the stable
// Name() of a serialized failure.
const (
	SelfSignedInvocationErrorName = "SelfSignedInvocation"
	InvalidSubjectErrorName       = "InvalidSubject"
	UnauthorizedErrorName         = "Unauthorized"
)

var (
	// ErrSelfSignedInvocation is returned when an invocation's issuer is its own
	// subject. Such an invocation carries the subject's full authority with no
	// proofs, so anyone holding any key can produce one.
	ErrSelfSignedInvocation = ucanerrors.New(SelfSignedInvocationErrorName, "an invocation may not be issued by its own subject")
	// ErrInvalidSubject is returned when an invocation is subjected to anyone but
	// the subject the command is served for.
	ErrInvalidSubject = ucanerrors.New(InvalidSubjectErrorName, "the subject of this invocation is not one this command is served for")
	// ErrUnauthorized is returned when an invocation's issuer is not the one
	// entitled to the command.
	ErrUnauthorized = ucanerrors.New(UnauthorizedErrorName, "the issuer of this invocation may not perform this operation")
)

// Middleware returns a route whose handler runs a check before the command. It
// is given the whole route, so a check can read the command it guards, and
// anything it derives from the route is computed once rather than per
// invocation. The route is a value: a middleware wraps its handler and returns
// it, leaving the caller's copy alone.
type Middleware func(route server.Route) server.Route

// Apply returns the routes with each middleware wrapped around them, the first
// one outermost. The routes it was given are unchanged.
func Apply(routes []server.Route, middleware ...Middleware) []server.Route {
	applied := make([]server.Route, 0, len(routes))
	for _, r := range routes {
		for i := len(middleware) - 1; i >= 0; i-- {
			r = middleware[i](r)
		}
		applied = append(applied, r)
	}
	return applied
}

// NotSelfSigned rejects an invocation issued by its own subject. Such an
// invocation proves nothing: the subject is the root of authority, so an
// invocation it issues needs no proofs and claims everything the subject can do.
// A command behind this check requires authority that came from somewhere else.
func NotSelfSigned() Middleware {
	return check(func(req execution.Request) error {
		inv := req.Invocation()
		if inv.Issuer() == inv.Subject() {
			return ErrSelfSignedInvocation
		}
		return nil
	})
}

// OnlySubject rejects an invocation subjected to anyone but subject, so the
// authority a caller presents has to trace back to that subject rather than to
// a key the caller owns.
func OnlySubject(subject did.DID) Middleware {
	return check(func(req execution.Request) error {
		if req.Invocation().Subject() != subject {
			return ErrInvalidSubject
		}
		return nil
	})
}

// OnlyIssuer rejects an invocation issued by anyone but issuer. It guards the
// commands a service invokes on itself, which are self-signed by definition and
// so cannot sit behind [NotSelfSigned]: what makes them safe is that only the
// service's own key can produce them.
func OnlyIssuer(issuer did.DID) Middleware {
	return check(func(req execution.Request) error {
		if req.Invocation().Issuer() != issuer {
			return ErrUnauthorized
		}
		return nil
	})
}

// check builds a middleware from a rule applied to each invocation. A rejected
// invocation gets the rule's error as its failure and is dropped from the
// batch; the next handler runs with the rest, or not at all when none remain.
// A route without a handler is returned as it is, so registering it still
// panics rather than failing on the first request.
func check(rule func(execution.Request) error) Middleware {
	return func(route server.Route) server.Route {
		next := route.Handler
		if next == nil {
			return route
		}
		route.Handler = func(items []execution.Batch) error {
			accepted := make([]execution.Batch, 0, len(items))
			for _, item := range items {
				if err := rule(item.Request); err != nil {
					if err := item.Response.SetFailure(err); err != nil {
						return err
					}
					continue
				}
				accepted = append(accepted, item)
			}
			if len(accepted) == 0 {
				return nil
			}
			return next(accepted)
		}
		return route
	}
}
