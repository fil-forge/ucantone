package plc_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/stretchr/testify/require"
)

func TestDirectoryClientLast(t *testing.T) {
	endpoint := mustParseURL(t, "https://plc.example")
	d, err := did.Parse("did:plc:7iza6de2dwap2sbkpav7c6c6")
	require.NoError(t, err)

	// A signed operation to round-trip through the directory.
	op := sampleSignedOperation(t)
	var opJSON bytes.Buffer
	require.NoError(t, op.MarshalDagJSON(&opJSON))

	t.Run("fetches the last signed operation", func(t *testing.T) {
		var gotReq *http.Request
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			return stringResponse(http.StatusOK, opJSON.String()), nil
		})
		c, err := plc.NewDirectoryClient(endpoint, plc.WithTransport(rt))
		require.NoError(t, err)

		got, err := c.Last(t.Context(), d)
		require.NoError(t, err)
		require.Equal(t, op, got)

		require.Equal(t, "GET", gotReq.Method)
		require.True(t, strings.HasSuffix(gotReq.URL.Path, d.String()+"/log/last"), "path %s should end with %s/log/last", gotReq.URL.Path, d.String())
	})

	t.Run("rejects a non-plc DID", func(t *testing.T) {
		c, err := plc.NewDirectoryClient(endpoint, plc.WithTransport(roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return stringResponse(http.StatusOK, opJSON.String()), nil
		})))
		require.NoError(t, err)

		web, err := did.Parse("did:web:example.com")
		require.NoError(t, err)
		_, err = c.Last(t.Context(), web)
		require.ErrorContains(t, err, "expected plc")
	})

	t.Run("errors on non-200 status", func(t *testing.T) {
		c, err := plc.NewDirectoryClient(endpoint, plc.WithTransport(roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return stringResponse(http.StatusNotFound, "not found"), nil
		})))
		require.NoError(t, err)

		_, err = c.Last(t.Context(), d)
		require.ErrorContains(t, err, "unexpected status")
	})

	t.Run("errors on a malformed body", func(t *testing.T) {
		c, err := plc.NewDirectoryClient(endpoint, plc.WithTransport(roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return stringResponse(http.StatusOK, "not json"), nil
		})))
		require.NoError(t, err)

		_, err = c.Last(t.Context(), d)
		require.ErrorContains(t, err, "parsing signed operation JSON")
	})

	t.Run("returns a DeactivatedDIDError when the last operation is a tombstone", func(t *testing.T) {
		tomb := plc.NewTombstone(testutil.RandomCID(t))
		signedTomb, err := plc.SignTombstone(testutil.RandomMultikeySigner(t), tomb)
		require.NoError(t, err)

		var tombJSON bytes.Buffer
		require.NoError(t, signedTomb.MarshalDagJSON(&tombJSON))

		c, err := plc.NewDirectoryClient(endpoint, plc.WithTransport(roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return stringResponse(http.StatusOK, tombJSON.String()), nil
		})))
		require.NoError(t, err)

		got, err := c.Last(t.Context(), d)
		require.Nil(t, got)
		require.Error(t, err)

		var deactErr *plc.DeactivatedDIDError
		require.ErrorAs(t, err, &deactErr)
		require.Equal(t, signedTomb, deactErr.Operation)
		require.Equal(t, "DID has been deactivated", err.Error())
	})

	t.Run("errors on a tombstone with no previous operation", func(t *testing.T) {
		c, err := plc.NewDirectoryClient(endpoint, plc.WithTransport(roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return stringResponse(http.StatusOK, `{"type":"plc_tombstone","sig":"c2ln"}`), nil
		})))
		require.NoError(t, err)

		_, err = c.Last(t.Context(), d)
		require.ErrorContains(t, err, "invalid tombstone operation: missing previous operation")

		var deactErr *plc.DeactivatedDIDError
		require.NotErrorAs(t, err, &deactErr)
	})
}

func TestDirectoryClientUpdate(t *testing.T) {
	endpoint := mustParseURL(t, "https://plc.example")
	d, err := did.Parse("did:plc:7iza6de2dwap2sbkpav7c6c6")
	require.NoError(t, err)

	op := sampleSignedOperation(t)

	t.Run("posts the signed operation as DagJSON", func(t *testing.T) {
		var gotReq *http.Request
		var gotBody []byte
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			b, err := readAll(req)
			require.NoError(t, err)
			gotBody = b
			return stringResponse(http.StatusOK, ""), nil
		})
		c, err := plc.NewDirectoryClient(endpoint, plc.WithTransport(rt))
		require.NoError(t, err)

		err = c.Update(t.Context(), d, op)
		require.NoError(t, err)

		require.Equal(t, "POST", gotReq.Method)
		require.True(t, strings.HasSuffix(gotReq.URL.Path, d.String()), "path %s should end with %s", gotReq.URL.Path, d.String())

		// The posted body decodes back to the published operation.
		var decoded plc.SignedOperation
		require.NoError(t, decoded.UnmarshalDagJSON(bytes.NewReader(gotBody)))
		require.Equal(t, op, &decoded)
	})

	t.Run("rejects a non-plc DID", func(t *testing.T) {
		c, err := plc.NewDirectoryClient(endpoint, plc.WithTransport(roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return stringResponse(http.StatusOK, ""), nil
		})))
		require.NoError(t, err)

		web, err := did.Parse("did:web:example.com")
		require.NoError(t, err)
		err = c.Update(t.Context(), web, op)
		require.ErrorContains(t, err, "expected plc")
	})

	t.Run("errors on non-200 status", func(t *testing.T) {
		c, err := plc.NewDirectoryClient(endpoint, plc.WithTransport(roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return stringResponse(http.StatusInternalServerError, "boom"), nil
		})))
		require.NoError(t, err)

		err = c.Update(t.Context(), d, op)
		require.ErrorContains(t, err, "unexpected status")
	})
}

func TestDirectoryClientDeactivate(t *testing.T) {
	endpoint := mustParseURL(t, "https://plc.example")
	d, err := did.Parse("did:plc:7iza6de2dwap2sbkpav7c6c6")
	require.NoError(t, err)

	tomb := sampleSignedTombstone(t)

	t.Run("posts the signed tombstone as DagJSON", func(t *testing.T) {
		var gotReq *http.Request
		var gotBody []byte
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			b, err := readAll(req)
			require.NoError(t, err)
			gotBody = b
			return stringResponse(http.StatusOK, ""), nil
		})
		c, err := plc.NewDirectoryClient(endpoint, plc.WithTransport(rt))
		require.NoError(t, err)

		err = c.Deactivate(t.Context(), d, tomb)
		require.NoError(t, err)

		require.Equal(t, "POST", gotReq.Method)
		require.True(t, strings.HasSuffix(gotReq.URL.Path, d.String()), "path %s should end with %s", gotReq.URL.Path, d.String())

		// The posted body decodes back to the published tombstone.
		var decoded plc.SignedTombstone
		require.NoError(t, decoded.UnmarshalDagJSON(bytes.NewReader(gotBody)))
		require.Equal(t, tomb, &decoded)
	})

	t.Run("rejects a non-plc DID", func(t *testing.T) {
		c, err := plc.NewDirectoryClient(endpoint, plc.WithTransport(roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return stringResponse(http.StatusOK, ""), nil
		})))
		require.NoError(t, err)

		web, err := did.Parse("did:web:example.com")
		require.NoError(t, err)
		err = c.Deactivate(t.Context(), web, tomb)
		require.ErrorContains(t, err, "expected plc")
	})

	t.Run("errors on non-200 status", func(t *testing.T) {
		c, err := plc.NewDirectoryClient(endpoint, plc.WithTransport(roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return stringResponse(http.StatusInternalServerError, "boom"), nil
		})))
		require.NoError(t, err)

		err = c.Deactivate(t.Context(), d, tomb)
		require.ErrorContains(t, err, "unexpected status")
	})
}

// sampleSignedOperation builds a fully-populated SignedOperation for round-trip
// tests. Slices and maps are non-empty so empty-vs-nil ambiguity in the codec
// doesn't affect equality assertions.
func sampleSignedOperation(t *testing.T) *plc.SignedOperation {
	t.Helper()
	vm, err := did.Parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
	require.NoError(t, err)
	rk, err := did.Parse("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
	require.NoError(t, err)
	return &plc.SignedOperation{
		Type:                plc.OperationType,
		VerificationMethods: map[string]did.DID{"atproto": vm},
		RotationKeys:        []did.DID{rk},
		AlsoKnownAs:         []string{"at://alice.example"},
		Services: map[string]plc.Service{
			"atproto_pds": {Type: "AtprotoPersonalDataServer", Endpoint: "https://pds.example"},
		},
		Signature: "c2lnbmF0dXJl",
	}
}

// sampleSignedTombstone builds a SignedTombstone for round-trip tests.
func sampleSignedTombstone(t *testing.T) *plc.SignedTombstone {
	t.Helper()
	return &plc.SignedTombstone{
		Type:      plc.TombstoneType,
		Previous:  testutil.RandomCID(t).String(),
		Signature: "c2lnbmF0dXJl",
	}
}

func readAll(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	defer req.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(req.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
