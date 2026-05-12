// Package result provides a typed sum value representing either a successful
// outcome (Ok branch) or a failure (Err branch). It's used as the return type
// of [github.com/fil-forge/ucantone/ucan.Receipt.Out].
package result

// Result is a typed sum: either an Ok value of type O or an Err value of type
// X. Construct with [OK] or [Err]; inspect with [Result.IsOk] or unpack into
// a Go (ok, err) pair with [Result.Unpack].
//
// Both branches are zero-valued when the other branch is set; use IsOk to
// disambiguate before reading the populated branch.
type Result[O, X any] struct {
	isOk bool
	ok   O
	err  X
}

// OK constructs a successful Result holding the given value.
func OK[O, X any](v O) Result[O, X] {
	return Result[O, X]{isOk: true, ok: v}
}

// Err constructs a failed Result holding the given value.
func Err[O, X any](v X) Result[O, X] {
	return Result[O, X]{err: v}
}

// IsOk reports whether the Ok branch is populated.
func (r Result[O, X]) IsOk() bool { return r.isOk }

// IsErr reports whether the Err branch is populated.
func (r Result[O, X]) IsErr() bool { return !r.isOk }

// Unpack returns the (ok, err) pair. The branch corresponding to !IsOk holds
// the zero value of its type.
func (r Result[O, X]) Unpack() (O, X) { return r.ok, r.err }
