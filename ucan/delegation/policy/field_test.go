package policy_test

import (
	"math/big"
	"testing"

	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/require"

	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	"github.com/fil-forge/ucantone/ucan/delegation/policy/policytest/fields"
)

// These tests author policies against generated field descriptors (see
// policytest/fields). The descriptor pins the comparison value type and the
// selector path, so the builders below could not be called with a wrong-typed
// value or a mistyped path — that would be a compile error.

func mustDigest(t *testing.T) multihash.Multihash {
	t.Helper()
	mh, err := multihash.Sum([]byte("hello"), multihash.SHA2_256, -1)
	require.NoError(t, err)
	return mh
}

// decodedArgs is what the selector sees after invocation args round-trip
// through CBOR: bytes are plain []byte, ints are int64, keys are strings.
func decodedArgs(digest multihash.Multihash, size int64) map[string]any {
	return map[string]any{
		"blob": map[string]any{
			"digest": []byte(digest),
			"size":   size,
		},
	}
}

func TestField_Comparisons(t *testing.T) {
	digest := mustDigest(t)

	pol, err := policy.Build(
		policy.Eq(fields.RetrieveArgs.Blob.Digest, digest), // value pinned to multihash.Multihash
		policy.Gte(fields.RetrieveArgs.Blob.Size, uint64(0)),
	)
	require.NoError(t, err)

	stmts := pol.Statements()
	require.Len(t, stmts, 2)
	require.Equal(t, policy.OpEqual, stmts[0].Operator())
	require.Equal(t, ".blob.digest", stmts[0].Selector())
	require.Equal(t, policy.OpGreaterThanOrEqual, stmts[1].Operator())
	require.Equal(t, ".blob.size", stmts[1].Selector())

	// The literal is canonicalized to plain []byte, so matching against the
	// decoded args succeeds.
	require.NoError(t, policy.Match(pol, decodedArgs(digest, 10)))

	// A different digest must not match.
	other := mustDigest(t)
	other[len(other)-1] ^= 0xff
	require.Error(t, policy.Match(pol, decodedArgs(other, 10)))
}

func TestField_Connectives(t *testing.T) {
	pol, err := policy.Build(
		policy.AnyOf(
			policy.Eq(fields.Manifest.Name, "alpha"),
			policy.Eq(fields.Manifest.Name, "beta"),
		),
		policy.Negate(policy.Eq(fields.Manifest.Name, "forbidden")),
	)
	require.NoError(t, err)

	stmts := pol.Statements()
	require.Len(t, stmts, 2)
	require.Equal(t, policy.OpOr, stmts[0].Operator())
	require.Equal(t, policy.OpNot, stmts[1].Operator())

	mk := func(name string) map[string]any {
		return map[string]any{"name": name, "shards": []any{}}
	}
	require.NoError(t, policy.Match(pol, mk("alpha")))
	require.NoError(t, policy.Match(pol, mk("beta")))
	require.Error(t, policy.Match(pol, mk("gamma")))     // matches neither branch of the or
	require.Error(t, policy.Match(pol, mk("forbidden"))) // hits the negate
}

func TestField_StringOrdering(t *testing.T) {
	// String ordering is lexicographic (matcher extension). The descriptor
	// makes Gt(Manifest.Name, ...) legal because Name is a string field.
	pol, err := policy.Build(policy.Gt(fields.Manifest.Name, "m"))
	require.NoError(t, err)

	mk := func(name string) map[string]any { return map[string]any{"name": name, "shards": []any{}} }
	require.NoError(t, policy.Match(pol, mk("ن"))) // "z..."-ish > "m"
	require.NoError(t, policy.Match(pol, mk("zeta")))
	require.Error(t, policy.Match(pol, mk("apple"))) // < "m"
}

func withShards(codecs ...int64) map[string]any {
	items := make([]any, len(codecs))
	for i, c := range codecs {
		items[i] = map[string]any{"codec": c}
	}
	return map[string]any{"name": "m", "shards": items}
}

func TestField_QuantifierEach(t *testing.T) {
	// Every shard must use codec 0x55 (raw). The closure receives the element
	// descriptor (element-relative selector paths).
	pol, err := policy.Build(
		policy.Each(fields.Manifest.Shards, func(s fields.ShardFields) []policy.StatementBuilderFunc {
			return []policy.StatementBuilderFunc{policy.Eq(s.Codec, uint64(0x55))}
		}),
	)
	require.NoError(t, err)

	stmts := pol.Statements()
	require.Len(t, stmts, 1)
	require.Equal(t, policy.OpAll, stmts[0].Operator())
	require.Equal(t, ".shards", stmts[0].Selector())

	require.NoError(t, policy.Match(pol, withShards(0x55, 0x55)))
	require.Error(t, policy.Match(pol, withShards(0x55, 0x71))) // one bad shard fails "all"
}

func TestField_QuantifierSome(t *testing.T) {
	pol, err := policy.Build(
		policy.Some(fields.Manifest.Shards, func(s fields.ShardFields) []policy.StatementBuilderFunc {
			return []policy.StatementBuilderFunc{policy.Gt(s.Codec, uint64(0x70))}
		}),
	)
	require.NoError(t, err)
	require.Equal(t, policy.OpAny, pol.Statements()[0].Operator())

	require.NoError(t, policy.Match(pol, withShards(0x55, 0x71))) // one shard > 0x70 satisfies "any"
	require.Error(t, policy.Match(pol, withShards(0x55, 0x55)))
}

// A *big.Int that overflows int64 must match by value, not pointer identity.
func TestField_BigInt(t *testing.T) {
	want := new(big.Int).Lsh(big.NewInt(1), 100) // 2^100, overflows int64

	pol, err := policy.Build(policy.Eq(fields.SignArgs.DataSet, want))
	require.NoError(t, err)
	require.Equal(t, ".dataSet", pol.Statements()[0].Selector())

	got := new(big.Int).Lsh(big.NewInt(1), 100)
	require.NotSame(t, want, got)
	require.NoError(t, policy.Match(pol, map[string]any{"dataSet": got}))
	require.Error(t, policy.Match(pol, map[string]any{"dataSet": big.NewInt(2)}))
}

func TestField_BigIntOrdering(t *testing.T) {
	threshold := new(big.Int).Lsh(big.NewInt(1), 64) // 2^64

	pol, err := policy.Build(policy.Gt(fields.SignArgs.DataSet, threshold))
	require.NoError(t, err)

	above := new(big.Int).Lsh(big.NewInt(1), 65)
	require.NoError(t, policy.Match(pol, map[string]any{"dataSet": above}))
	require.Error(t, policy.Match(pol, map[string]any{"dataSet": big.NewInt(5)}))
}

func TestField_QuantifierEachMap(t *testing.T) {
	// Every value in the meta map must match the glob.
	pol, err := policy.Build(
		policy.EachMap(fields.Labels.Meta, func(v policy.Selector[string]) []policy.StatementBuilderFunc {
			return []policy.StatementBuilderFunc{policy.Glob(v, "v-*")}
		}),
	)
	require.NoError(t, err)
	require.Equal(t, policy.OpAll, pol.Statements()[0].Operator())
	require.Equal(t, ".meta", pol.Statements()[0].Selector())

	require.NoError(t, policy.Match(pol, map[string]any{"meta": map[string]any{"a": "v-1", "b": "v-2"}}))
	require.Error(t, policy.Match(pol, map[string]any{"meta": map[string]any{"a": "v-1", "b": "bad"}}))
}

// A glob and a multi-constraint quantifier element (implicit AND) together.
func TestField_GlobAndElementGroup(t *testing.T) {
	pol, err := policy.Build(
		policy.Glob(fields.Manifest.Name, "blob-*"),
		policy.Each(fields.Manifest.Shards, func(s fields.ShardFields) []policy.StatementBuilderFunc {
			return []policy.StatementBuilderFunc{
				policy.Gte(s.Codec, uint64(0x50)),
				policy.Lte(s.Codec, uint64(0x60)),
			}
		}),
	)
	require.NoError(t, err)
	require.Len(t, pol.Statements(), 2)

	val := map[string]any{
		"name":   "blob-123",
		"shards": []any{map[string]any{"codec": int64(0x55)}},
	}
	require.NoError(t, policy.Match(pol, val))
}
