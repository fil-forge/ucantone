package testutil

import (
	"bytes"
	crand "crypto/rand"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/principal"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/require"
)

// ArgsMap decodes an invocation's args bytes into a generic datamodel.Map.
// Test convenience for echo handlers and ad-hoc key access; production code
// should decode ArgumentsBytes directly into a typed cborgen struct.
func ArgsMap(t *testing.T, inv ucan.Invocation) datamodel.Map {
	t.Helper()
	raw := inv.ArgumentsBytes()
	if len(raw) == 0 {
		return datamodel.Map{}
	}
	var m datamodel.Map
	require.NoError(t, m.UnmarshalCBOR(bytes.NewReader(raw)))
	return m
}

// ResultMap decodes raw CBOR bytes (e.g. from a Receipt.Out() branch) into a
// generic ipld.Map. Returns nil if raw is empty.
func ResultMap(t *testing.T, raw []byte) ipld.Map {
	t.Helper()
	if len(raw) == 0 {
		return nil
	}
	var m datamodel.Map
	require.NoError(t, m.UnmarshalCBOR(bytes.NewReader(raw)))
	return ipld.Map(m)
}

// Must takes return values from a function and returns the non-error one. If
// the error value is non-nil then it panics.
func Must[T any](val T, err error) func(t *testing.T) T {
	return func(t *testing.T) T {
		require.NoError(t, err)
		return val
	}
}

func RandomBytes(t *testing.T, size int) []byte {
	t.Helper()
	bytes := make([]byte, size)
	_, err := crand.Read(bytes)
	require.NoError(t, err)
	return bytes
}

func RandomCID(t *testing.T) cid.Cid {
	t.Helper()
	bytes := RandomBytes(t, 10)
	c, _ := cid.Prefix{
		Version:  1,
		Codec:    cid.Raw,
		MhType:   multihash.SHA2_256,
		MhLength: -1,
	}.Sum(bytes)
	return c
}

func RandomDigest(t *testing.T) multihash.Multihash {
	t.Helper()
	return RandomCID(t).Hash()
}

func RandomSigner(t *testing.T) principal.Signer {
	t.Helper()
	return Must(ed25519.Generate())(t)
}

func RandomDID(t *testing.T) did.DID {
	t.Helper()
	return RandomSigner(t).DID()
}
