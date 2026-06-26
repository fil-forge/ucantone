package plc_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/testutil"
	cid "github.com/ipfs/go-cid"
	multihash "github.com/multiformats/go-multihash/core"
	"github.com/stretchr/testify/require"
)

func TestNewOperation(t *testing.T) {
	t.Run("genesis operation has no previous", func(t *testing.T) {
		op := plc.NewOperation(nil)
		require.Equal(t, plc.OperationType, op.Type)
		require.Nil(t, op.Previous)
	})

	t.Run("chained operation references the previous CID string", func(t *testing.T) {
		prev := testutil.RandomCID(t)
		op := plc.NewOperation(&prev)
		require.NotNil(t, op.Previous)
		require.Equal(t, prev.String(), *op.Previous)
	})
}

func TestOperationOptions(t *testing.T) {
	t.Run("WithVerificationMethods merges map entries", func(t *testing.T) {
		a := testutil.RandomDID(t)
		b := testutil.RandomDID(t)
		op := plc.NewOperation(
			nil,
			plc.WithVerificationMethods(map[string]did.DID{"atproto": a}),
			plc.WithVerificationMethods(map[string]did.DID{"other": b}),
		)
		require.Equal(t, map[string]did.DID{"atproto": a, "other": b}, op.VerificationMethods)
	})

	t.Run("WithServices merges map entries", func(t *testing.T) {
		s1 := plc.Service{Type: "AtprotoPersonalDataServer", Endpoint: "https://pds.example"}
		s2 := plc.Service{Type: "Other", Endpoint: "https://other.example"}
		op := plc.NewOperation(
			nil,
			plc.WithServices(map[string]plc.Service{"atproto_pds": s1}),
			plc.WithServices(map[string]plc.Service{"other": s2}),
		)
		require.Equal(t, map[string]plc.Service{"atproto_pds": s1, "other": s2}, op.Services)
	})

	t.Run("WithRotationKeys appends", func(t *testing.T) {
		a := testutil.RandomDID(t)
		b := testutil.RandomDID(t)
		op := plc.NewOperation(
			nil,
			plc.WithRotationKeys([]did.DID{a}),
			plc.WithRotationKeys([]did.DID{b}),
		)
		require.Equal(t, []did.DID{a, b}, op.RotationKeys)
	})

	t.Run("WithAlsoKnownAs appends", func(t *testing.T) {
		op := plc.NewOperation(
			nil,
			plc.WithAlsoKnownAs([]string{"at://alice.example"}),
			plc.WithAlsoKnownAs([]string{"at://alice.other"}),
		)
		require.Equal(t, []string{"at://alice.example", "at://alice.other"}, op.AlsoKnownAs)
	})

	t.Run("WithoutVerificationMethods removes map entries by key", func(t *testing.T) {
		a := testutil.RandomDID(t)
		b := testutil.RandomDID(t)
		op := plc.NewOperation(
			nil,
			plc.WithVerificationMethods(map[string]did.DID{"atproto": a, "other": b}),
			// Value is ignored: removal is keyed on the map key.
			plc.WithoutVerificationMethods(map[string]did.DID{"atproto": testutil.RandomDID(t)}),
		)
		require.Equal(t, map[string]did.DID{"other": b}, op.VerificationMethods)
	})

	t.Run("WithoutServices removes map entries by key", func(t *testing.T) {
		s1 := plc.Service{Type: "AtprotoPersonalDataServer", Endpoint: "https://pds.example"}
		s2 := plc.Service{Type: "Other", Endpoint: "https://other.example"}
		op := plc.NewOperation(
			nil,
			plc.WithServices(map[string]plc.Service{"atproto_pds": s1, "other": s2}),
			plc.WithoutServices(map[string]plc.Service{"other": {}}),
		)
		require.Equal(t, map[string]plc.Service{"atproto_pds": s1}, op.Services)
	})

	t.Run("WithoutRotationKeys removes the given keys", func(t *testing.T) {
		a := testutil.RandomDID(t)
		b := testutil.RandomDID(t)
		c := testutil.RandomDID(t)
		op := plc.NewOperation(
			nil,
			plc.WithRotationKeys([]did.DID{a, b, c}),
			plc.WithoutRotationKeys([]did.DID{a, c}),
		)
		require.Equal(t, []did.DID{b}, op.RotationKeys)
	})

	t.Run("WithoutRotationKeys ignores absent keys", func(t *testing.T) {
		a := testutil.RandomDID(t)
		op := plc.NewOperation(
			nil,
			plc.WithRotationKeys([]did.DID{a}),
			plc.WithoutRotationKeys([]did.DID{testutil.RandomDID(t)}),
		)
		require.Equal(t, []did.DID{a}, op.RotationKeys)
	})

	t.Run("WithoutAlsoKnownAs removes the given entries", func(t *testing.T) {
		op := plc.NewOperation(
			nil,
			plc.WithAlsoKnownAs([]string{"at://x.example", "at://y.example", "at://z.example"}),
			plc.WithoutAlsoKnownAs([]string{"at://y.example"}),
		)
		require.Equal(t, []string{"at://x.example", "at://z.example"}, op.AlsoKnownAs)
	})
}

func TestNewFromPreviousOperation(t *testing.T) {
	t.Run("inherits previous fields, merges options, links to previous CID", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		vm := testutil.RandomDID(t)
		rk := testutil.RandomDID(t)

		_, genesis, err := plc.New(
			signer,
			plc.WithVerificationMethods(map[string]did.DID{"atproto": vm}),
			plc.WithRotationKeys([]did.DID{rk}),
			plc.WithAlsoKnownAs([]string{"at://alice.example"}),
		)
		require.NoError(t, err)

		newRotationKey := testutil.RandomDID(t)
		next, err := plc.NewFromPreviousOperation(
			genesis,
			plc.WithRotationKeys([]did.DID{newRotationKey}),
		)
		require.NoError(t, err)

		// Inherited from previous.
		require.Equal(t, genesis.VerificationMethods, next.VerificationMethods)
		require.Equal(t, genesis.AlsoKnownAs, next.AlsoKnownAs)
		// Merged: previous rotation keys + the new one (appended).
		require.Equal(t, []did.DID{rk, newRotationKey}, next.RotationKeys)

		// Previous link is the CID of the CBOR-encoded previous signed operation.
		var prevBytes bytes.Buffer
		require.NoError(t, genesis.MarshalCBOR(&prevBytes))
		expectedLink, err := cid.V1Builder{
			Codec:  cid.DagCBOR,
			MhType: multihash.SHA2_256,
		}.Sum(prevBytes.Bytes())
		require.NoError(t, err)

		require.NotNil(t, next.Previous)
		require.Equal(t, expectedLink.String(), *next.Previous)
	})

	t.Run("removes inherited values via Without options", func(t *testing.T) {
		signer := testutil.RandomMultikeySigner(t)
		vmA := testutil.RandomDID(t)
		vmB := testutil.RandomDID(t)
		rkA := testutil.RandomDID(t)
		rkB := testutil.RandomDID(t)

		_, genesis, err := plc.New(
			signer,
			plc.WithVerificationMethods(map[string]did.DID{"atproto": vmA, "other": vmB}),
			plc.WithRotationKeys([]did.DID{rkA, rkB}),
		)
		require.NoError(t, err)

		next, err := plc.NewFromPreviousOperation(
			genesis,
			plc.WithoutRotationKeys([]did.DID{rkA}),
			plc.WithoutVerificationMethods(map[string]did.DID{"atproto": testutil.RandomDID(t)}),
		)
		require.NoError(t, err)

		// Exactly the named entries are removed from the inherited collections.
		require.Equal(t, []did.DID{rkB}, next.RotationKeys)
		require.Equal(t, map[string]did.DID{"other": vmB}, next.VerificationMethods)
	})
}

func TestNewTombstone(t *testing.T) {
	prev := testutil.RandomCID(t)
	tomb := plc.NewTombstone(prev)
	require.Equal(t, plc.TombstoneType, tomb.Type)
	require.Equal(t, prev.String(), tomb.Previous)
}

func TestNewTombstoneFromPreviousOperation(t *testing.T) {
	signer := testutil.RandomMultikeySigner(t)
	_, prev, err := plc.New(signer, plc.WithRotationKeys([]did.DID{testutil.RandomDID(t)}))
	require.NoError(t, err)

	tomb, err := plc.NewTombstoneFromPreviousOperation(prev)
	require.NoError(t, err)
	require.Equal(t, plc.TombstoneType, tomb.Type)

	// The previous link matches the CID computed from the previous operation's
	// CBOR encoding — the same link NewFromPreviousOperation would produce.
	var prevBytes bytes.Buffer
	require.NoError(t, prev.MarshalCBOR(&prevBytes))
	expectedLink, err := cid.V1Builder{
		Codec:  cid.DagCBOR,
		MhType: multihash.SHA2_256,
	}.Sum(prevBytes.Bytes())
	require.NoError(t, err)
	require.Equal(t, expectedLink.String(), tomb.Previous)

	next, err := plc.NewFromPreviousOperation(prev)
	require.NoError(t, err)
	require.NotNil(t, next.Previous)
	require.Equal(t, *next.Previous, tomb.Previous)
}

func TestSerializationRoundTrip(t *testing.T) {
	vm := testutil.RandomDID(t)
	rk := testutil.RandomDID(t)
	prev := testutil.RandomCID(t).String()
	svc := map[string]plc.Service{
		"atproto_pds": {Type: "AtprotoPersonalDataServer", Endpoint: "https://pds.example"},
	}

	t.Run("Operation (genesis, nil previous)", func(t *testing.T) {
		op := &plc.Operation{
			Type:                plc.OperationType,
			VerificationMethods: map[string]did.DID{"atproto": vm},
			RotationKeys:        []did.DID{rk},
			AlsoKnownAs:         []string{"at://alice.example"},
			Services:            svc,
			Previous:            nil,
		}
		t.Run("CBOR", func(t *testing.T) {
			var got plc.Operation
			roundTripCBOR(t, op, &got)
			require.Equal(t, op, &got)
		})
		t.Run("DagJSON", func(t *testing.T) {
			var got plc.Operation
			roundTripDagJSON(t, op, &got)
			require.Equal(t, op, &got)
		})
	})

	t.Run("Operation (chained, with previous)", func(t *testing.T) {
		op := &plc.Operation{
			Type:                plc.OperationType,
			VerificationMethods: map[string]did.DID{"atproto": vm},
			RotationKeys:        []did.DID{rk},
			AlsoKnownAs:         []string{"at://alice.example"},
			Services:            svc,
			Previous:            &prev,
		}
		t.Run("CBOR", func(t *testing.T) {
			var got plc.Operation
			roundTripCBOR(t, op, &got)
			require.Equal(t, op, &got)
		})
		t.Run("DagJSON", func(t *testing.T) {
			var got plc.Operation
			roundTripDagJSON(t, op, &got)
			require.Equal(t, op, &got)
		})
	})

	t.Run("SignedOperation", func(t *testing.T) {
		op := &plc.SignedOperation{
			Type:                plc.OperationType,
			VerificationMethods: map[string]did.DID{"atproto": vm},
			RotationKeys:        []did.DID{rk},
			AlsoKnownAs:         []string{"at://alice.example"},
			Services:            svc,
			Previous:            &prev,
			Signature:           "c2lnbmF0dXJl",
		}
		t.Run("CBOR", func(t *testing.T) {
			var got plc.SignedOperation
			roundTripCBOR(t, op, &got)
			require.Equal(t, op, &got)
		})
		t.Run("DagJSON", func(t *testing.T) {
			var got plc.SignedOperation
			roundTripDagJSON(t, op, &got)
			require.Equal(t, op, &got)
		})
	})

	t.Run("Service", func(t *testing.T) {
		s := &plc.Service{Type: "AtprotoPersonalDataServer", Endpoint: "https://pds.example"}
		t.Run("CBOR", func(t *testing.T) {
			var got plc.Service
			roundTripCBOR(t, s, &got)
			require.Equal(t, s, &got)
		})
		t.Run("DagJSON", func(t *testing.T) {
			var got plc.Service
			roundTripDagJSON(t, s, &got)
			require.Equal(t, s, &got)
		})
	})

	t.Run("Tombstone", func(t *testing.T) {
		tomb := &plc.Tombstone{Type: plc.TombstoneType, Previous: prev}
		t.Run("CBOR", func(t *testing.T) {
			var got plc.Tombstone
			roundTripCBOR(t, tomb, &got)
			require.Equal(t, tomb, &got)
		})
		t.Run("DagJSON", func(t *testing.T) {
			var got plc.Tombstone
			roundTripDagJSON(t, tomb, &got)
			require.Equal(t, tomb, &got)
		})
	})

	t.Run("SignedTombstone", func(t *testing.T) {
		st := &plc.SignedTombstone{Type: plc.TombstoneType, Previous: prev, Signature: "c2ln"}
		t.Run("CBOR", func(t *testing.T) {
			var got plc.SignedTombstone
			roundTripCBOR(t, st, &got)
			require.Equal(t, st, &got)
		})
		t.Run("DagJSON", func(t *testing.T) {
			var got plc.SignedTombstone
			roundTripDagJSON(t, st, &got)
			require.Equal(t, st, &got)
		})
	})
}

type cborMarshaler interface {
	MarshalCBOR(w io.Writer) error
}

type cborUnmarshaler interface {
	UnmarshalCBOR(r io.Reader) error
}

type dagJSONMarshaler interface {
	MarshalDagJSON(w io.Writer) error
}

type dagJSONUnmarshaler interface {
	UnmarshalDagJSON(r io.Reader) error
}

func roundTripCBOR(t *testing.T, in cborMarshaler, out cborUnmarshaler) {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, in.MarshalCBOR(&buf))
	require.NoError(t, out.UnmarshalCBOR(bytes.NewReader(buf.Bytes())))
}

func roundTripDagJSON(t *testing.T, in dagJSONMarshaler, out dagJSONUnmarshaler) {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, in.MarshalDagJSON(&buf))
	require.NoError(t, out.UnmarshalDagJSON(bytes.NewReader(buf.Bytes())))
}
