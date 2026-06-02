package varsig_test

import (
	"encoding/base64"
	"testing"

	"github.com/fil-forge/ucantone/varsig"
	"github.com/fil-forge/ucantone/varsig/algorithm/ecdsa"
	"github.com/fil-forge/ucantone/varsig/algorithm/eddsa"
	"github.com/stretchr/testify/require"
)

func TestVarsigEd25519DagCbor(t *testing.T) {
	vs := varsig.New(eddsa.Ed25519, varsig.DagCbor)

	require.Equal(t, uint64(1), vs.Version())
	require.Equal(t, eddsa.Ed25519, vs.SignatureAlgorithm())
	require.Equal(t, varsig.DagCbor, vs.PayloadEncoding())

	data, err := vs.Encode()
	require.NoError(t, err)

	t.Log("Encoded (base64):")
	t.Logf("\t%s", base64.RawStdEncoding.EncodeToString(data))

	decodedVs, n, err := varsig.Decode(data)
	require.NoError(t, err)
	require.Equal(t, len(data), n)

	require.Equal(t, vs, decodedVs)
}

func TestVarsigSecp256k1DagCbor(t *testing.T) {
	vs := varsig.New(ecdsa.Secp256k1, varsig.DagCbor)

	require.Equal(t, uint64(1), vs.Version())
	require.Equal(t, ecdsa.Secp256k1, vs.SignatureAlgorithm())
	require.Equal(t, varsig.DagCbor, vs.PayloadEncoding())

	data, err := vs.Encode()
	require.NoError(t, err)

	t.Log("Encoded (base64):")
	t.Logf("\t%s", base64.RawStdEncoding.EncodeToString(data))

	decodedVs, n, err := varsig.Decode(data)
	require.NoError(t, err)
	require.Equal(t, len(data), n)

	require.Equal(t, vs, decodedVs)
}
