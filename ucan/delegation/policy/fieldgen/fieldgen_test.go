package fieldgen

import (
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/require"

	"github.com/fil-forge/ucantone/ucan/delegation/policy/policytest"
)

func TestIsLeaf(t *testing.T) {
	leaf := func(v any) bool { return isLeaf(reflect.TypeOf(v)) }

	require.True(t, leaf(""))                       // string
	require.True(t, leaf(uint64(0)))                // integer
	require.True(t, leaf([]byte(nil)))              // bytes
	require.True(t, leaf(multihash.Multihash(nil))) // named byte slice
	require.True(t, leaf(cid.Cid{}))                // struct, no exported fields
	require.True(t, leaf((*big.Int)(nil)))          // pointer to leaf

	require.False(t, leaf(policytest.Blob{}))     // struct with exported fields
	require.False(t, leaf(policytest.Manifest{})) // navigable
}

func TestNavStruct(t *testing.T) {
	blob := reflect.TypeOf(policytest.Blob{})

	require.Equal(t, blob, navStruct(reflect.TypeOf(policytest.Blob{})))  // struct
	require.Equal(t, blob, navStruct(reflect.TypeOf(&policytest.Blob{}))) // pointer is dereferenced

	require.Nil(t, navStruct(reflect.TypeOf([]policytest.Shard(nil)))) // slice, not a struct
	require.Nil(t, navStruct(reflect.TypeOf((*big.Int)(nil))))         // leaf
	require.Nil(t, navStruct(reflect.TypeOf("")))                      // scalar
}

func TestIPLDKey(t *testing.T) {
	env := reflect.TypeOf(policytest.Envelope{})
	fallback, _ := env.FieldByName("Fallback")
	require.Equal(t, "fallback", ipldKey(fallback)) // ",omitempty" stripped

	blob := reflect.TypeOf(policytest.Blob{})
	digest, _ := blob.FieldByName("Digest")
	require.Equal(t, "digest", ipldKey(digest))

	// No cborgen tag falls back to the Go field name (cbor-gen's default).
	type noTag struct{ Foo string }
	foo, _ := reflect.TypeOf(noTag{}).FieldByName("Foo")
	require.Equal(t, "Foo", ipldKey(foo))
}

// TestWriteFieldDescriptors generates descriptors for the policytest fixtures
// and asserts the structural invariants of the output. WriteFieldDescriptors
// runs gofmt internally, so a nil error already means the source is valid Go;
// these checks pin the paths, generic type arguments, and naming scheme.
func TestWriteFieldDescriptors(t *testing.T) {
	out := filepath.Join(t.TempDir(), "policy_fields_gen.go")
	err := WriteFieldDescriptors(out, "fields",
		policytest.Blob{},
		policytest.RetrieveArgs{},
		policytest.Shard{},
		policytest.Manifest{},
		policytest.SignArgs{},
		policytest.Envelope{},
		policytest.Tagged{},
		policytest.Bundle{},
	)
	require.NoError(t, err)

	b, err := os.ReadFile(out)
	require.NoError(t, err)
	s := string(b)

	wantContains := []string{
		// named leaf types are preserved (not decomposed to []uint8)
		"policy.Selector[multihash.Multihash]",
		"policy.Selector[*big.Int]",
		// nested struct field -> absolute selector path
		`policy.NewSelector[multihash.Multihash](".blob.digest")`,
		// slice of struct -> SliceSelector of the element descriptor type
		"policy.SliceSelector[ShardFields]",
		`policy.NewSliceSelector[ShardFields](".shards"`,
		// slice of scalar -> SliceSelector of an identity Selector
		"policy.SliceSelector[policy.Selector[string]]",
		`policy.NewSelector[string](".")`,
		// pointer-to-struct field dereferenced, occupying the same path
		`policy.NewSelector[multihash.Multihash](".fallback.digest")`,
		// slice element struct with a nested struct: paths are element-relative
		`policy.NewSliceSelector[EnvelopeFields](".items"`,
		`policy.NewSelector[multihash.Multihash](".primary.digest")`,
		// entry var named after the type; descriptor type is <T>Fields
		"type BlobFields struct",
		"var Blob = BlobFields{",
		// explicit import alias matches the real package name
		`multihash "github.com/multiformats/go-multihash"`,
	}
	for _, w := range wantContains {
		require.Contains(t, s, w, "generated output should contain %q", w)
	}

	// Quantifier element paths are element-relative, not absolute.
	require.NotContains(t, s, ".shards.codec")
	require.NotContains(t, s, ".items.primary") // nested-in-element stays element-relative
	// The target package is never self-imported.
	require.NotContains(t, s, `"github.com/fil-forge/ucantone/ucan/delegation/policy/policytest"`)
}
