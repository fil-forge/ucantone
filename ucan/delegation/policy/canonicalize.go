package policy

import (
	"fmt"
	"math"
	"math/big"
	"reflect"

	"github.com/ipfs/go-cid"
)

// canonicalize lowers an arbitrary Go value to its canonical IPLD
// representation so that policy literals compare and serialize the same way
// invocation arguments do once they have round-tripped through CBOR.
//
// It dispatches on reflect.Kind rather than concrete type, so named types
// whose underlying type is supported — multihash.Multihash (~[]byte),
// a custom Size (~uint64), etc. — are handled transparently. This is what
// removes the need for callers to pre-cast (e.g. []byte(digest)) and what
// keeps reflect.DeepEqual in matching from failing on type identity
// (multihash.Multihash{…} vs the []byte the selector decodes).
//
// The canonical kinds mirror datamodel.Any's supported set:
//
//	nil | bool | int64 | string | []byte | cid.Cid | []any | map[string]any
//
// Integers that overflow int64 are kept as *big.Int (CBOR bignum), the one
// integer kind that does not collapse to int64; see [normalizeBigInt].
func canonicalize(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	// cid.Cid and big.Int are structs; match them before the reflect path,
	// which would treat any struct as unsupported.
	switch x := v.(type) {
	case cid.Cid:
		return x, nil
	case *big.Int:
		if x == nil {
			return nil, nil
		}
		return normalizeBigInt(x), nil
	case big.Int:
		return normalizeBigInt(&x), nil
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Bool:
		return rv.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		u := rv.Uint()
		if u > math.MaxInt64 {
			// Too big for int64 but still a valid non-negative integer: carry
			// it as a CBOR bignum rather than failing.
			return new(big.Int).SetUint64(u), nil
		}
		return int64(u), nil
	case reflect.String:
		return rv.String(), nil
	case reflect.Slice, reflect.Array:
		// A slice/array of bytes (incl. named types like multihash.Multihash)
		// is IPLD Bytes, not an IPLD List.
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, rv.Len())
			reflect.Copy(reflect.ValueOf(b), rv)
			return b, nil
		}
		out := make([]any, rv.Len())
		for i := range rv.Len() {
			cv, err := canonicalize(rv.Index(i).Interface())
			if err != nil {
				return nil, fmt.Errorf("list index %d: %w", i, err)
			}
			out[i] = cv
		}
		return out, nil
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("map keys must be strings, got %s", rv.Type().Key())
		}
		out := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			cv, err := canonicalize(iter.Value().Interface())
			if err != nil {
				return nil, fmt.Errorf("map key %q: %w", iter.Key().String(), err)
			}
			out[iter.Key().String()] = cv
		}
		return out, nil
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil, nil
		}
		return canonicalize(rv.Elem().Interface())
	}
	return nil, fmt.Errorf("unsupported type for IPLD value: %T", v)
}

// normalizeBigInt lowers a CBOR bignum to the canonical integer form: a plain
// int64 when it fits (so it shares the common, well-trodden int64 path and
// compares equal to int64-encoded values), otherwise the *big.Int as-is for
// magnitudes that overflow int64. Matching treats both via [asBigInt]. This
// mirrors how datamodel.Any now decodes/encodes bignums (CBOR tag 2); see
// NOTE-bigint-datamodel.md.
func normalizeBigInt(x *big.Int) any {
	if x.IsInt64() {
		return x.Int64()
	}
	return x
}

// normalizeValue is the error-swallowing form used on the matching hot path,
// where a value that cannot be canonicalized is simply left as-is for the
// downstream comparison to reject.
func normalizeValue(v any) any {
	if cv, err := canonicalize(v); err == nil {
		return cv
	}
	return v
}
