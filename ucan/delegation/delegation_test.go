package delegation_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/principal/secp256k1"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/stretchr/testify/require"
)

func TestDelegation(t *testing.T) {
	t.Run("minimal", func(t *testing.T) {
		issuer := testutil.RandomSigner(t)
		audience := testutil.RandomDID(t)
		command := testutil.Must(command.Parse("/test/invoke"))(t)
		then := ucan.Now()

		initial, err := delegation.Delegate(issuer, audience, did.Undef, command)
		require.NoError(t, err)

		encoded, err := delegation.Encode(initial)
		require.NoError(t, err)

		decoded, err := delegation.Decode(encoded)
		require.NoError(t, err)

		require.Equal(t, issuer.DID(), decoded.Issuer())
		require.Equal(t, audience, decoded.Audience())
		require.Equal(t, command, decoded.Command())
		require.False(t, decoded.Subject().Defined())
		require.NotEmpty(t, decoded.Nonce())
		require.GreaterOrEqual(t, *decoded.Expiration(), then)
	})

	t.Run("secp256k1", func(t *testing.T) {
		issuer := testutil.Must(secp256k1.Generate())(t)
		audience := testutil.RandomDID(t)
		command := testutil.Must(command.Parse("/test/invoke"))(t)

		dlg, err := delegation.Delegate(issuer, audience, did.Undef, command)
		require.NoError(t, err)

		encoded, err := delegation.Encode(dlg)
		require.NoError(t, err)

		decoded, err := delegation.Decode(encoded)
		require.NoError(t, err)

		ok, err := delegation.VerifySignature(decoded, issuer.Verifier())
		require.NoError(t, err)
		require.True(t, ok)
	})
}

type PayloadModel struct {
	Iss   string
	Aud   string
	Sub   string
	Cmd   string
	Pol   []string
	Exp   int
	Nonce string
}

type EnvelopeModel struct {
	Payload   PayloadModel
	Signature string
	Alg       string
	Enc       string
	Spec      string
	Version   string
}

type ValidModel struct {
	Name     string
	Token    string
	Cid      string
	Envelope EnvelopeModel
}

type FixturesModel struct {
	Version    string
	Comments   string
	Principals map[string]string
	Valid      []ValidModel
}

// https://github.com/ucan-wg/spec/tree/main/fixtures/1.0.0/delegation.json
func TestFixtures(t *testing.T) {
	fixtureBytes := testutil.Must(os.ReadFile("./testdata/fixtures/delegation.json"))(t)

	var fixtures FixturesModel
	err := json.Unmarshal(fixtureBytes, &fixtures)
	require.NoError(t, err)

	principals := map[string]ucan.Signer{}
	for name, skstr := range fixtures.Principals {
		bytes := testutil.Must(base64.StdEncoding.DecodeString(skstr))(t)
		signer := testutil.Must(ed25519.Decode(bytes))(t)
		principals[signer.DID().String()] = signer
		t.Logf("%s: %s", name, signer.DID())
	}

	for _, vector := range fixtures.Valid {
		t.Run(vector.Name, func(t *testing.T) {
			expectedBytes := testutil.Must(base64.StdEncoding.DecodeString(vector.Token))(t)
			_, err := delegation.Decode(expectedBytes)
			require.NoError(t, err)

			issuer := principals[vector.Envelope.Payload.Iss]
			audience := principals[vector.Envelope.Payload.Aud]
			subject := testutil.Must(did.Parse(vector.Envelope.Payload.Sub))(t)
			command := testutil.Must(command.Parse(vector.Envelope.Payload.Cmd))(t)
			expiration := ucan.UnixTimestamp(vector.Envelope.Payload.Exp)
			nonce := testutil.Must(base64.StdEncoding.DecodeString(vector.Envelope.Payload.Nonce))(t)
			signature := testutil.Must(base64.StdEncoding.DecodeString(vector.Envelope.Signature))(t)

			actual, err := delegation.Delegate(
				issuer,
				audience.DID(),
				subject,
				command,
				delegation.WithExpiration(expiration),
				delegation.WithNonce(nonce),
			)
			require.NoError(t, err)
			require.Equal(t, signature, actual.Signature().Bytes())

			actualBytes, err := delegation.Encode(actual)
			require.NoError(t, err)
			require.Equal(t, expectedBytes, actualBytes)
		})
	}
}
