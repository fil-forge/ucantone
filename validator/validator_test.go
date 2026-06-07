package validator_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/validator"
	verrs "github.com/fil-forge/ucantone/validator/errors"
	fdm "github.com/fil-forge/ucantone/validator/internal/fixtures/datamodel"
	"github.com/fil-forge/ucantone/verification/absentee"
)

const (
	past   ucan.UnixTimestamp = 1000000000 // 2001-09-09
	future ucan.UnixTimestamp = 9999999999 // 2286-11-20
	now    ucan.UnixTimestamp = 1746748800 // 2025-05-09 (fixed validation time for tests)
)

// badIssuer is a Signer that produces invalid signatures, for testing purposes.
type badIssuer struct{ ucan.Issuer }

func (b badIssuer) Sign(msg []byte) []byte {
	sig := b.Issuer.Sign(msg)
	sig[0] ^= 0xff // flip a bit
	return sig
}

func TestValidate(t *testing.T) {
	crankWidget := testutil.Must(command.Parse("/widget/crank"))(t)

	t.Run("validates with root authority", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		inv, err := invocation.Invoke(subject, subject.DID(), crankWidget, datamodel.Map{})
		require.NoError(t, err)

		err = validator.ValidateInvocation(t.Context(), inv)
		require.NoError(t, err)
	})

	t.Run("rejects with a bad signature", func(t *testing.T) {
		subject := badIssuer{testutil.RandomIssuer(t)}
		inv, err := invocation.Invoke(subject, subject.DID(), crankWidget, datamodel.Map{})
		require.NoError(t, err)

		err = validator.ValidateInvocation(t.Context(), inv)
		require.Error(t, err)
	})

	t.Run("rejects with unauthorized invoker", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		invoker := testutil.RandomIssuer(t)

		inv, err := invocation.Invoke(subject, invoker.DID(), crankWidget, datamodel.Map{})
		require.NoError(t, err)

		err = validator.ValidateInvocation(t.Context(), inv)
		require.Error(t, err)
	})

	t.Run("validates with subject → invoker", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		invoker := testutil.RandomIssuer(t)

		del, err := delegation.Delegate(subject, invoker.DID(), subject.DID(), crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			invoker,
			subject.DID(),
			crankWidget,
			datamodel.Map{},
			invocation.WithProofs(del.Link()),
		)
		require.NoError(t, err)

		err = validator.ValidateInvocation(
			t.Context(),
			inv,
			validator.WithProofResolver(
				validator.ProofsFromContainer(
					container.New(container.WithDelegations(del)),
				),
			),
		)
		require.NoError(t, err)
	})

	t.Run("rejects an expired invocation", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		inv, err := invocation.Invoke(subject, subject.DID(), crankWidget, datamodel.Map{},
			invocation.WithExpiration(past),
		)
		require.NoError(t, err)

		err = validator.ValidateInvocation(t.Context(), inv, validator.WithValidationTime(now))
		require.Error(t, err)
	})

	t.Run("accepts an invocation with a future expiry", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		inv, err := invocation.Invoke(subject, subject.DID(), crankWidget, datamodel.Map{},
			invocation.WithExpiration(future),
		)
		require.NoError(t, err)

		err = validator.ValidateInvocation(t.Context(), inv, validator.WithValidationTime(now))
		require.NoError(t, err)
	})

	t.Run("rejects a proof that is not yet valid", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		invoker := testutil.RandomIssuer(t)

		del, err := delegation.Delegate(subject, invoker.DID(), subject.DID(), crankWidget,
			delegation.WithNotBefore(future),
		)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			invoker,
			subject.DID(),
			crankWidget,
			datamodel.Map{},
			invocation.WithProofs(del.Link()),
		)
		require.NoError(t, err)

		err = validator.ValidateInvocation(
			t.Context(),
			inv,
			validator.WithValidationTime(now),
			validator.WithProofResolver(
				validator.ProofsFromContainer(
					container.New(container.WithDelegations(del)),
				),
			),
		)
		require.Error(t, err)
	})

	t.Run("rejects when final proof audience does not match invoker", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		invoker := testutil.RandomIssuer(t)
		other := testutil.RandomIssuer(t)

		// Delegation goes to other, but invoker invokes
		del, err := delegation.Delegate(subject, other.DID(), subject.DID(), crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			invoker,
			subject.DID(),
			crankWidget,
			datamodel.Map{},
			invocation.WithProofs(del.Link()),
		)
		require.NoError(t, err)

		err = validator.ValidateInvocation(
			t.Context(),
			inv,
			validator.WithProofResolver(
				validator.ProofsFromContainer(
					container.New(container.WithDelegations(del)),
				),
			),
		)
		require.Error(t, err)
	})

	t.Run("rejects a broken mid-chain (issuer mismatch)", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		bob := testutil.RandomIssuer(t)
		eve := testutil.RandomIssuer(t)

		del1, err := delegation.Delegate(subject, alice.DID(), subject.DID(), crankWidget)
		require.NoError(t, err)
		// del2 is from eve, not alice — breaks the chain
		del2, err := delegation.Delegate(eve, bob.DID(), subject.DID(), crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			bob,
			subject.DID(),
			crankWidget,
			datamodel.Map{},
			invocation.WithProofs(del1.Link(), del2.Link()),
		)
		require.NoError(t, err)

		err = validator.ValidateInvocation(
			t.Context(),
			inv,
			validator.WithProofResolver(
				validator.ProofsFromContainer(
					container.New(container.WithDelegations(del1, del2)),
				),
			),
		)
		require.Error(t, err)
	})

	t.Run("validates with subject → alice → bob", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		bob := testutil.RandomIssuer(t)

		del1, err := delegation.Delegate(subject, alice.DID(), subject.DID(), crankWidget)
		require.NoError(t, err)
		del2, err := delegation.Delegate(alice, bob.DID(), subject.DID(), crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			bob,
			subject.DID(),
			crankWidget,
			datamodel.Map{},
			invocation.WithProofs(del1.Link(), del2.Link()),
		)
		require.NoError(t, err)

		err = validator.ValidateInvocation(
			t.Context(),
			inv,
			validator.WithProofResolver(
				validator.ProofsFromContainer(
					container.New(container.WithDelegations(del1, del2)),
				),
			),
		)
		require.NoError(t, err)
	})

	t.Run("rejects when a referenced proof cannot be resolved", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		invoker := testutil.RandomIssuer(t)

		del, err := delegation.Delegate(subject, invoker.DID(), subject.DID(), crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			invoker,
			subject.DID(),
			crankWidget,
			datamodel.Map{},
			invocation.WithProofs(del.Link()),
		)
		require.NoError(t, err)

		// No WithProofResolver — default ProofUnavailable fires
		err = validator.ValidateInvocation(t.Context(), inv)
		require.Error(t, err)
	})

	// https://github.com/ucan-wg/delegation#powerline
	t.Run("validates with powerline delegation in chain", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		bob := testutil.RandomIssuer(t)

		del1, err := delegation.Delegate(subject, alice.DID(), subject.DID(), crankWidget)
		require.NoError(t, err)
		// del2 is a powerline delegation, where alice delegates `/widget/crank` to
		// bob for any subject she herself is authorized to `/widget/crank`.
		del2, err := delegation.Delegate(alice, bob.DID(), did.Undef, crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			bob,
			subject.DID(),
			crankWidget,
			datamodel.Map{},
			invocation.WithProofs(del1.Link(), del2.Link()),
		)
		require.NoError(t, err)

		err = validator.ValidateInvocation(
			t.Context(),
			inv,
			validator.WithProofResolver(
				validator.ProofsFromContainer(
					container.New(container.WithDelegations(del1, del2)),
				),
			),
		)
		require.NoError(t, err)
	})

	// Explicitly disallowed by spec:
	// https://github.com/ucan-wg/delegation#powerline
	t.Run("rejects a powerline delegation at root of chain", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		invoker := testutil.RandomIssuer(t)

		// Root delegation has nil subject — invalid per spec.
		del, err := delegation.Delegate(subject, invoker.DID(), did.Undef, crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			invoker,
			subject.DID(),
			crankWidget,
			datamodel.Map{},
			invocation.WithProofs(del.Link()),
		)
		require.NoError(t, err)

		err = validator.ValidateInvocation(
			t.Context(),
			inv,
			validator.WithProofResolver(
				validator.ProofsFromContainer(
					container.New(container.WithDelegations(del)),
				),
			),
		)
		require.Error(t, err)
	})

	t.Run("accepts a proof with a NotBefore in the past", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		invoker := testutil.RandomIssuer(t)

		del, err := delegation.Delegate(subject, invoker.DID(), subject.DID(), crankWidget,
			delegation.WithNotBefore(past),
		)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			invoker,
			subject.DID(),
			crankWidget,
			datamodel.Map{},
			invocation.WithProofs(del.Link()),
		)
		require.NoError(t, err)

		err = validator.ValidateInvocation(
			t.Context(),
			inv,
			validator.WithValidationTime(now),
			validator.WithProofResolver(
				validator.ProofsFromContainer(
					container.New(container.WithDelegations(del)),
				),
			),
		)
		require.NoError(t, err)
	})

	t.Run("with a policy on a delegation", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		invoker := testutil.RandomIssuer(t)

		del, err := delegation.Delegate(subject, invoker.DID(), subject.DID(), crankWidget,
			delegation.WithPolicyBuilder(policy.Equal(".answer", 42)),
		)
		require.NoError(t, err)

		resolveProof := validator.ProofsFromContainer(
			container.New(container.WithDelegations(del)),
		)

		t.Run("accepts an invocation whose arguments satisfy the policy", func(t *testing.T) {
			inv, err := invocation.Invoke(
				invoker,
				subject.DID(),
				crankWidget,
				datamodel.Map{"answer": 42},
				invocation.WithProofs(del.Link()),
			)
			require.NoError(t, err)

			err = validator.ValidateInvocation(
				t.Context(),
				inv,
				validator.WithProofResolver(resolveProof),
			)
			require.NoError(t, err)
		})

		t.Run("rejects an invocation whose arguments violate the policy", func(t *testing.T) {
			inv, err := invocation.Invoke(
				invoker,
				subject.DID(),
				crankWidget,
				datamodel.Map{"answer": 41},
				invocation.WithProofs(del.Link()),
			)
			require.NoError(t, err)

			err = validator.ValidateInvocation(
				t.Context(),
				inv,
				validator.WithProofResolver(resolveProof),
			)
			require.Error(t, err)
		})
	})

	t.Run("rejects with incorrect subject in chain", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		bob := testutil.RandomIssuer(t)
		unrelatedSubject := testutil.RandomIssuer(t)

		del1, err := delegation.Delegate(subject, alice.DID(), subject.DID(), crankWidget)
		require.NoError(t, err)
		// del2 is about the wrong subject.
		del2, err := delegation.Delegate(alice, bob.DID(), unrelatedSubject.DID(), crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			bob,
			subject.DID(),
			crankWidget,
			datamodel.Map{},
			invocation.WithProofs(del1.Link(), del2.Link()),
		)
		require.NoError(t, err)

		err = validator.ValidateInvocation(
			t.Context(),
			inv,
			validator.WithProofResolver(
				validator.ProofsFromContainer(
					container.New(container.WithDelegations(del1, del2)),
				),
			),
		)
		require.Error(t, err)
	})

	t.Run("rejects when the signing key is expired", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)

		// Build a DID document with an expired Multikey VM.
		expires := did.DateTimeStamp(time.Unix(int64(past), 0))
		resolver := expiredKeyResolver(t, subject, &expires, nil)

		inv, err := invocation.Invoke(subject, subject.DID(), crankWidget, datamodel.Map{})
		require.NoError(t, err)

		err = validator.ValidateInvocation(t.Context(), inv,
			validator.WithDIDResolver(resolver),
			validator.WithValidationTime(now),
		)
		require.ErrorContains(t, err, "expired")
	})

	t.Run("rejects when the signing key is revoked", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)

		revoked := did.DateTimeStamp(time.Unix(int64(past), 0))
		resolver := expiredKeyResolver(t, subject, nil, &revoked)

		inv, err := invocation.Invoke(subject, subject.DID(), crankWidget, datamodel.Map{})
		require.NoError(t, err)

		err = validator.ValidateInvocation(t.Context(), inv,
			validator.WithDIDResolver(resolver),
			validator.WithValidationTime(now),
		)
		require.ErrorContains(t, err, "revoked")
	})

	t.Run("accepts when the signing key has not yet expired", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)

		expires := did.DateTimeStamp(time.Unix(int64(future), 0))
		resolver := expiredKeyResolver(t, subject, &expires, nil)

		inv, err := invocation.Invoke(subject, subject.DID(), crankWidget, datamodel.Map{})
		require.NoError(t, err)

		err = validator.ValidateInvocation(t.Context(), inv,
			validator.WithDIDResolver(resolver),
			validator.WithValidationTime(now),
		)
		require.NoError(t, err)
	})

	t.Run("with non-standard signature in chain", func(t *testing.T) {
		subject := testutil.RandomIssuer(t)
		alice := absentee.From(testutil.Must(did.Parse("did:example:alice"))(t))
		bob := testutil.RandomIssuer(t)

		del1, err := delegation.Delegate(subject, alice.DID(), subject.DID(), crankWidget)
		require.NoError(t, err)
		// del2 is "signed" by alice, who is an absentee signer and produces a
		// non-standard signature.
		del2, err := delegation.Delegate(alice, bob.DID(), did.Undef, crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			bob,
			subject.DID(),
			crankWidget,
			datamodel.Map{},
			invocation.WithProofs(del1.Link(), del2.Link()),
		)
		require.NoError(t, err)

		resolveProof := validator.ProofsFromContainer(
			container.New(container.WithDelegations(del1, del2)),
		)

		t.Run("rejects by default", func(t *testing.T) {
			err = validator.ValidateInvocation(
				t.Context(),
				inv,
				validator.WithProofResolver(resolveProof),
				validator.WithDIDResolver(did.ResolverMap{
					"key": key.Resolver,
					"example": did.ResolverFunc(func(ctx context.Context, d did.DID) (did.Document, error) {
						require.Fail(t, "shouldn't try to resolve a verifier for a non-standard signature")
						return did.Document{}, nil
					}),
				}),
			)
			require.ErrorContains(t, err, "no non-standard signature verifier configured")
		})

		t.Run("rejects according to non-standard signature verifier", func(t *testing.T) {
			err = validator.ValidateInvocation(
				t.Context(),
				inv,
				validator.WithProofResolver(resolveProof),
				validator.WithNonStandardSignatureVerifier(
					func(ctx context.Context, token ucan.Token, meta ucan.Container) error {
						require.Equal(t, del2.Link(), token.Link(), "should be asked to verify the non-standard signature for the correct token")
						return errors.New("non-standard error failed as expected")
					},
				),
			)
			require.ErrorContains(t, err, "non-standard error failed as expected")
		})

		t.Run("validates according to non-standard signature verifier", func(t *testing.T) {
			err = validator.ValidateInvocation(
				t.Context(),
				inv,
				validator.WithProofResolver(resolveProof),
				validator.WithNonStandardSignatureVerifier(
					func(ctx context.Context, token ucan.Token, meta ucan.Container) error {
						require.Equal(t, del2.Link(), token.Link(), "should be asked to verify the non-standard signature for the correct token")
						return nil
					},
				),
			)
			require.NoError(t, err)
		})
	})
}

// expiredKeyResolver returns a DID resolver that serves a document for the
// issuer's DID with its Multikey VM marked expired or revoked as specified.
func expiredKeyResolver(t *testing.T, issuer ucan.Issuer, expires, revoked *did.DateTimeStamp) did.Resolver {
	t.Helper()
	return did.ResolverFunc(func(_ context.Context, d did.DID) (did.Document, error) {
		doc := did.NewDocument(d)
		vm := did.VerificationMethod{
			ID:         doc.Fragment(d.Identifier()),
			Controller: d,
			Expires:    expires,
			Revoked:    revoked,
			Type:       did.MultikeyVerificationMethodType,
			Material:   did.GenericMap{did.MultikeyPublicKeyMultibaseProp: d.Identifier()},
		}
		if err := doc.VerificationMethods.Add(vm); err != nil {
			return did.Document{}, err
		}
		for _, rel := range []*did.VerificationRelationship{
			doc.Authentication, doc.AssertionMethod,
			doc.CapabilityDelegation, doc.CapabilityInvocation,
		} {
			if err := rel.Add(vm); err != nil {
				return did.Document{}, err
			}
		}
		return doc, nil
	})
}

type StubVerifier struct {
	did          did.DID
	resolverUsed string
}

func (s StubVerifier) DID() did.DID {
	return s.did
}

func (s StubVerifier) Verify(msg []byte, sig []byte) bool {
	return false
}

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

			opts := []validator.Option{
				validator.WithValidationTime(ucan.UnixTimestamp(vector.Time)),
				validator.WithProofResolver(newMapProofResolver(proofs)),
			}

			err = validator.ValidateInvocation(t.Context(), inv, opts...)
			require.NoError(t, err, "validation should have passed for invocation with %s", vector.Description)
		})
	}

	for _, vector := range fixtures.Invalid {
		t.Run("invalid "+vector.Name, func(t *testing.T) {

			inv, err := invocation.Decode(vector.Invocation)
			require.NoError(t, err)
			t.Log("invocation", inv.Link())

			proofs := decodeProofs(t, vector.Proofs)

			opts := []validator.Option{
				validator.WithValidationTime(ucan.UnixTimestamp(vector.Time)),
				validator.WithProofResolver(newMapProofResolver(proofs)),
			}

			err = validator.ValidateInvocation(t.Context(), inv, opts...)
			require.Error(t, err, "validation should not have passed for invocation because %s", vector.Description)
			t.Log(err)

			var namedErr NamedError
			require.True(t, errors.As(err, &namedErr))
			require.Equal(t, vector.Error.Name, namedErr.Name())
		})
	}
}

func newMapProofResolver(proofs map[cid.Cid]ucan.Delegation) validator.ProofResolverFunc {
	return func(_ context.Context, link cid.Cid) (ucan.Delegation, error) {
		dlg, ok := proofs[link]
		if !ok {
			return nil, verrs.NewUnavailableProofError(link, errors.New("not provided"))
		}
		return dlg, nil
	}
}

func decodeProofs(t *testing.T, vectorProofs [][]byte) map[cid.Cid]ucan.Delegation {
	proofs := map[cid.Cid]ucan.Delegation{}
	for _, p := range vectorProofs {
		dlg, err := delegation.Decode(p)
		require.NoError(t, err)
		proofs[dlg.Link()] = dlg
		t.Log("proof", dlg.Link())
	}
	return proofs
}
