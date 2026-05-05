package signer_test

import (
	"testing"

	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/principal/signer"
	"github.com/stretchr/testify/require"
)

func TestFormatParse(t *testing.T) {
	s0, err := ed25519.Generate()
	require.NoError(t, err)

	t.Log(s0.DID().String())

	str := signer.Format(s0)
	t.Log(str)

	s1, err := ed25519.Parse(str)
	require.NoError(t, err)

	t.Log(s1.DID().String())
	require.Equal(t, s0.DID(), s1.DID(), "public key mismatch")
}
