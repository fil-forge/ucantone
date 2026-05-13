package validator_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/principal/absentee"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/validator"
	"github.com/fil-forge/ucantone/validator/capability"
	verrs "github.com/fil-forge/ucantone/validator/errors"
	fdm "github.com/fil-forge/ucantone/validator/internal/fixtures/datamodel"
	"github.com/stretchr/testify/require"
)

type NamedError interface {
	error
	Name() string
}

func TestFixtures(t *testing.T) {
	fixturesFile, err := os.Open("./internal/fixtures/invocations.json")
	require.NoError(t, err)

	var fixtures fdm.FixturesModel
	err = fixtures.UnmarshalDagJSON(fixturesFile)
	require.NoError(t, err)

	for _, vector := range fixtures.Valid {
		t.Run("valid "+vector.Name, func(t *testing.T) {
			inv, err := invocation.Decode(vector.Invocation)
			require.NoError(t, err)
			t.Log("invocation", inv.Link())

			proofs := decodeProofs(t, vector.Proofs)
			authority, err := ed25519.Generate()
			require.NoError(t, err)
			vrf := authority.Verifier()

			// TODO: capability details in the vector?
			cmd, err := command.Parse("/msg/send")
			require.NoError(t, err)

			opts := []validator.Option{
				validator.WithValidationTime(vector.Time),
				validator.WithProofResolver(newMapProofResolver(proofs)),
			}
			cap, err := capability.New(cmd)
			require.NoError(t, err)

			_, err = validator.Access(t.Context(), vrf, cap, inv, opts...)
			require.NoError(t, err, "validation should have passed for invocation with %s", vector.Description)
		})
	}

	for _, vector := range fixtures.Invalid {
		t.Run("invalid "+vector.Name, func(t *testing.T) {
			inv, err := invocation.Decode(vector.Invocation)
			require.NoError(t, err)
			t.Log("invocation", inv.Link())

			proofs := decodeProofs(t, vector.Proofs)
			authority, err := ed25519.Generate()
			require.NoError(t, err)
			vrf := authority.Verifier()

			// TODO: capability details in the vector?
			cmd, err := command.Parse("/msg/send")
			require.NoError(t, err)

			opts := []validator.Option{
				validator.WithValidationTime(vector.Time),
				validator.WithProofResolver(newMapProofResolver(proofs)),
			}
			cap, err := capability.New(cmd)
			require.NoError(t, err)

			_, err = validator.Access(t.Context(), vrf, cap, inv, opts...)
			require.Error(t, err, "validation should not have passed for invocation because %s", vector.Description)
			t.Log(err)

			var namedErr NamedError
			require.True(t, errors.As(err, &namedErr))
			require.Equal(t, vector.Error.Name, namedErr.Name())
		})
	}
}

func TestNonStandardSignatureVerification(t *testing.T) {
	space := testutil.RandomSigner(t)
	account := absentee.From(testutil.Must(did.Parse("did:mailto:web.mail:alice"))(t))
	service := testutil.RandomSigner(t)

	BlobAdd, err := capability.New("/blob/add")
	require.NoError(t, err)

	// space -> account
	accountDlg, err := BlobAdd.Delegate(space, account.DID(), space.DID())
	require.NoError(t, err)

	inv, err := BlobAdd.Invoke(
		account,
		space.DID(),
		datamodel.Map{"digest": []byte(testutil.RandomDigest(t))},
		invocation.WithAudience(service.DID()),
		invocation.WithProofs(accountDlg.Link()),
	)
	require.NoError(t, err)

	auth, err := validator.Access(
		t.Context(),
		service.Verifier(),
		BlobAdd,
		inv,
		validator.WithProofs(accountDlg),
		validator.WithNonStandardSignatureVerifier(
			func(ctx context.Context, token ucan.Token, meta ucan.Container) error {
				if token.Link() != inv.Link() {
					return verrs.NewUnverifiableSignatureError(token, errors.New("unexpected verification token"))
				}
				return nil
			},
		),
	)
	require.NoError(t, err)
	t.Log(auth)
}

func TestNonStandardSignatureVerificationViaAttestation(t *testing.T) {
	space := testutil.RandomSigner(t)
	account := absentee.From(testutil.Must(did.Parse("did:mailto:web.mail:alice"))(t))
	service := testutil.RandomSigner(t)
	agent := testutil.RandomSigner(t)

	BlobAdd, err := capability.New("/blob/add")
	require.NoError(t, err)

	Attest, err := capability.New("/ucan/attest")
	require.NoError(t, err)

	// space -> account
	accountDlg, err := BlobAdd.Delegate(space, account.DID(), space.DID())
	require.NoError(t, err)

	// account -> agent
	agentDlg, err := BlobAdd.Delegate(account, agent.DID(), space.DID())
	require.NoError(t, err)

	// service attests to the delegation from the account to the agent
	args := datamodel.Map{"proof": agentDlg.Link()}
	attestation, err := Attest.Invoke(service, agent.DID(), args)
	require.NoError(t, err)

	inv, err := BlobAdd.Invoke(
		agent,
		space.DID(),
		datamodel.Map{"digest": []byte(testutil.RandomDigest(t))},
		invocation.WithAudience(service.DID()),
		invocation.WithProofs(accountDlg.Link(), agentDlg.Link()),
	)
	require.NoError(t, err)

	auth, err := validator.Access(
		t.Context(),
		service.Verifier(),
		BlobAdd,
		inv,
		validator.WithProofs(accountDlg, agentDlg),
		// include the attestation when validating
		validator.WithMetadata(container.New(container.WithInvocations(attestation))),
		validator.WithNonStandardSignatureVerifier(
			// This is a contrived example of a non-standard signature verification
			// function that checks for the presence of a trusted attestation in the
			// validation metadata instead of verifying a cryptographic signature.
			func(ctx context.Context, token ucan.Token, meta ucan.Container) error {
				for _, inv := range meta.Invocations() {
					// Typically one would validate the attestation invocation's signature
					// and check its claims, but for this example we'll just check that it
					// attests to the token we're trying to verify.
					if inv.Command() == Attest.Command() && testutil.ArgsMap(t, inv)["proof"] == token.Link() {
						return nil
					}
				}
				return verrs.NewUnverifiableSignatureError(token, errors.New("no matching attestation found"))
			},
		),
	)
	require.NoError(t, err)
	t.Log(auth)
}

func newMapProofResolver(proofs map[ucan.Link]ucan.Delegation) validator.ProofResolverFunc {
	return func(_ context.Context, link ucan.Link) (ucan.Delegation, error) {
		dlg, ok := proofs[link]
		if !ok {
			return nil, verrs.NewUnavailableProofError(link, errors.New("not provided"))
		}
		return dlg, nil
	}
}

func decodeProofs(t *testing.T, vectorProofs [][]byte) map[ucan.Link]ucan.Delegation {
	proofs := map[ucan.Link]ucan.Delegation{}
	for _, p := range vectorProofs {
		dlg, err := delegation.Decode(p)
		require.NoError(t, err)
		proofs[dlg.Link()] = dlg
		t.Log("proof", dlg.Link())
	}
	return proofs
}
