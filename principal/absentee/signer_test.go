package absentee_test

import (
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal/absentee"
	"github.com/stretchr/testify/require"
)

func TestAbsentee(t *testing.T) {
	t.Run("it can sign", func(t *testing.T) {
		alicedid, err := did.Parse("did:mailto:web.mail:alice")
		require.NoError(t, err)

		signer := absentee.From(alicedid)
		require.Equal(t, alicedid, signer.DID())
		require.Equal(t, absentee.SignatureAlgorithm, signer.SignatureAlgorithm())

		sig := signer.Sign([]byte("hello world"))
		require.Equal(t, []byte{}, sig)
	})
}
