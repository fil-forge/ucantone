package execution_test

import (
	"fmt"
	"io"
	"testing"

	"github.com/fil-forge/ucantone/errors"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/stretchr/testify/require"
)

// regionMismatch stands in for a downstream failure that carries a field of its
// own: a named error that encodes its own CBOR so the field reaches the caller.
type regionMismatch struct{ expected string }

func (e *regionMismatch) Name() string  { return "RegionMismatch" }
func (e *regionMismatch) Error() string { return "bucket is served by another region" }

func (e *regionMismatch) MarshalCBOR(w io.Writer) error {
	m := datamodel.Map{
		"name":     e.Name(),
		"message":  e.Error(),
		"expected": e.expected,
	}
	return m.MarshalCBOR(w)
}

func TestSetFailure(t *testing.T) {
	issuer := testutil.RandomIssuer(t)

	// setFailure records err as the response's failure and decodes the receipt's
	// error branch back into a generic map, which is what a caller reads.
	setFailure := func(t *testing.T, err error) ipld.Map {
		t.Helper()
		res, resErr := execution.NewResponse(testutil.RandomCID(t), execution.WithIssuer(issuer))
		require.NoError(t, resErr)
		require.NoError(t, res.SetFailure(err))
		_, errBytes := res.Receipt().Out().Unpack()
		return testutil.ResultMap(t, errBytes)
	}

	t.Run("a failure that encodes its own CBOR is marshaled by itself", func(t *testing.T) {
		out := setFailure(t, &regionMismatch{expected: "eu-west-1"})
		require.Equal(t, "RegionMismatch", out["name"])
		require.Equal(t, "eu-west-1", out["expected"])
	})

	t.Run("a wrapped failure that encodes its own CBOR keeps its fields", func(t *testing.T) {
		// The handler adds context with %w; the failure still travels as its own
		// model, so the field the caller acts on survives the wrapping.
		out := setFailure(t, fmt.Errorf("authorizing: %w", &regionMismatch{expected: "eu-west-1"}))
		require.Equal(t, "RegionMismatch", out["name"])
		require.Equal(t, "eu-west-1", out["expected"])
	})

	t.Run("a wrapped named error travels as its name and full message", func(t *testing.T) {
		// A named error that encodes nothing of its own keeps the wrapping context
		// in its message, under the name the caller matches on.
		err := errors.New("UnknownBucket", "unknown bucket")
		out := setFailure(t, fmt.Errorf("authorizing: %w", err))
		require.Equal(t, "UnknownBucket", out["name"])
		require.Equal(t, "authorizing: unknown bucket", out["message"])
	})

	t.Run("an unnamed error travels as UnknownError", func(t *testing.T) {
		out := setFailure(t, fmt.Errorf("boom"))
		require.Equal(t, "UnknownError", out["name"])
		require.Equal(t, "boom", out["message"])
	})

	t.Run("a response without an issuer cannot record a failure", func(t *testing.T) {
		res, err := execution.NewResponse(testutil.RandomCID(t))
		require.NoError(t, err)
		require.Error(t, res.SetFailure(fmt.Errorf("boom")))
	})
}
