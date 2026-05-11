package validator2_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/principal/absentee"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/principal/secp256k1"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/validator2"
)

const (
	past   ucan.UTCUnixTimestamp = 1000000000 // 2001-09-09
	future ucan.UTCUnixTimestamp = 9999999999 // 2286-11-20
	now    ucan.UTCUnixTimestamp = 1746748800 // 2025-05-09 (fixed validation time for tests)
)

// badSigner is a Signer that produces invalid signatures, for testing purposes.
type badSigner struct{ ucan.Signer }

func (b badSigner) Sign(msg []byte) []byte {
	sig := b.Signer.Sign(msg)
	sig[0] ^= 0xff // flip a bit
	return sig
}

func TestValidate(t *testing.T) {
	crankWidget := testutil.Must(command.Parse("/widget/crank"))(t)

	t.Run("validates with root authority", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		inv, err := invocation.Invoke(subject, subject, crankWidget, ipld.Map{})
		require.NoError(t, err)

		err = validator2.ValidateInvocation(t.Context(), inv)
		require.NoError(t, err)
	})

	t.Run("rejects with a bad signature", func(t *testing.T) {
		subject := badSigner{testutil.RandomSigner(t)}
		inv, err := invocation.Invoke(subject, subject, crankWidget, ipld.Map{})
		require.NoError(t, err)

		err = validator2.ValidateInvocation(t.Context(), inv)
		require.Error(t, err)
	})

	t.Run("rejects with unauthorized invoker", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		invoker := testutil.RandomSigner(t)

		inv, err := invocation.Invoke(subject, invoker, crankWidget, ipld.Map{})
		require.NoError(t, err)

		err = validator2.ValidateInvocation(t.Context(), inv)
		require.Error(t, err)
	})

	t.Run("validates with subject → invoker", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		invoker := testutil.RandomSigner(t)

		del, err := delegation.Delegate(subject, invoker, subject, crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			invoker,
			subject,
			crankWidget,
			ipld.Map{},
			invocation.WithProofs(del.Link()),
		)
		require.NoError(t, err)

		err = validator2.ValidateInvocation(
			t.Context(),
			inv,
			validator2.WithProofResolver(
				validator2.ProofsFromContainer(
					container.New(container.WithDelegations(del)),
				),
			),
		)
		require.NoError(t, err)
	})

	t.Run("rejects an expired invocation", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		inv, err := invocation.Invoke(subject, subject, crankWidget, ipld.Map{},
			invocation.WithExpiration(past),
		)
		require.NoError(t, err)

		err = validator2.ValidateInvocation(t.Context(), inv, validator2.WithValidationTime(now))
		require.Error(t, err)
	})

	t.Run("accepts an invocation with a future expiry", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		inv, err := invocation.Invoke(subject, subject, crankWidget, ipld.Map{},
			invocation.WithExpiration(future),
		)
		require.NoError(t, err)

		err = validator2.ValidateInvocation(t.Context(), inv, validator2.WithValidationTime(now))
		require.NoError(t, err)
	})

	t.Run("rejects a proof that is not yet valid", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		invoker := testutil.RandomSigner(t)

		del, err := delegation.Delegate(subject, invoker, subject, crankWidget,
			delegation.WithNotBefore(future),
		)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			invoker,
			subject,
			crankWidget,
			ipld.Map{},
			invocation.WithProofs(del.Link()),
		)
		require.NoError(t, err)

		err = validator2.ValidateInvocation(
			t.Context(),
			inv,
			validator2.WithValidationTime(now),
			validator2.WithProofResolver(
				validator2.ProofsFromContainer(
					container.New(container.WithDelegations(del)),
				),
			),
		)
		require.Error(t, err)
	})

	t.Run("rejects when final proof audience does not match invoker", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		invoker := testutil.RandomSigner(t)
		other := testutil.RandomSigner(t)

		// Delegation goes to other, but invoker invokes
		del, err := delegation.Delegate(subject, other, subject, crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			invoker,
			subject,
			crankWidget,
			ipld.Map{},
			invocation.WithProofs(del.Link()),
		)
		require.NoError(t, err)

		err = validator2.ValidateInvocation(
			t.Context(),
			inv,
			validator2.WithProofResolver(
				validator2.ProofsFromContainer(
					container.New(container.WithDelegations(del)),
				),
			),
		)
		require.Error(t, err)
	})

	t.Run("rejects a broken mid-chain (issuer mismatch)", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		alice := testutil.RandomSigner(t)
		bob := testutil.RandomSigner(t)
		eve := testutil.RandomSigner(t)

		del1, err := delegation.Delegate(subject, alice, subject, crankWidget)
		require.NoError(t, err)
		// del2 is from eve, not alice — breaks the chain
		del2, err := delegation.Delegate(eve, bob, subject, crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			bob,
			subject,
			crankWidget,
			ipld.Map{},
			invocation.WithProofs(del1.Link(), del2.Link()),
		)
		require.NoError(t, err)

		err = validator2.ValidateInvocation(
			t.Context(),
			inv,
			validator2.WithProofResolver(
				validator2.ProofsFromContainer(
					container.New(container.WithDelegations(del1, del2)),
				),
			),
		)
		require.Error(t, err)
	})

	t.Run("validates with subject → alice → bob", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		alice := testutil.RandomSigner(t)
		bob := testutil.RandomSigner(t)

		del1, err := delegation.Delegate(subject, alice, subject, crankWidget)
		require.NoError(t, err)
		del2, err := delegation.Delegate(alice, bob, subject, crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			bob,
			subject,
			crankWidget,
			ipld.Map{},
			invocation.WithProofs(del1.Link(), del2.Link()),
		)
		require.NoError(t, err)

		err = validator2.ValidateInvocation(
			t.Context(),
			inv,
			validator2.WithProofResolver(
				validator2.ProofsFromContainer(
					container.New(container.WithDelegations(del1, del2)),
				),
			),
		)
		require.NoError(t, err)
	})

	t.Run("rejects when a referenced proof cannot be resolved", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		invoker := testutil.RandomSigner(t)

		del, err := delegation.Delegate(subject, invoker, subject, crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			invoker,
			subject,
			crankWidget,
			ipld.Map{},
			invocation.WithProofs(del.Link()),
		)
		require.NoError(t, err)

		// No WithProofResolver — default ProofUnavailable fires
		err = validator2.ValidateInvocation(t.Context(), inv)
		require.Error(t, err)
	})

	// https://github.com/ucan-wg/delegation#powerline
	t.Run("validates with powerline delegation in chain", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		alice := testutil.RandomSigner(t)
		bob := testutil.RandomSigner(t)

		del1, err := delegation.Delegate(subject, alice, subject, crankWidget)
		require.NoError(t, err)
		// del2 is a powerline delegation, where alice delegates `/widget/crank` to
		// bob for any subject she herself is authorized to `/widget/crank`.
		del2, err := delegation.Delegate(alice, bob, nil, crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			bob,
			subject,
			crankWidget,
			ipld.Map{},
			invocation.WithProofs(del1.Link(), del2.Link()),
		)
		require.NoError(t, err)

		err = validator2.ValidateInvocation(
			t.Context(),
			inv,
			validator2.WithProofResolver(
				validator2.ProofsFromContainer(
					container.New(container.WithDelegations(del1, del2)),
				),
			),
		)
		require.NoError(t, err)
	})

	// Explicitly disallowed by spec:
	// https://github.com/ucan-wg/delegation#powerline
	t.Run("rejects a powerline delegation at root of chain", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		invoker := testutil.RandomSigner(t)

		// Root delegation has nil subject — invalid per spec.
		del, err := delegation.Delegate(subject, invoker, nil, crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			invoker,
			subject,
			crankWidget,
			ipld.Map{},
			invocation.WithProofs(del.Link()),
		)
		require.NoError(t, err)

		err = validator2.ValidateInvocation(
			t.Context(),
			inv,
			validator2.WithProofResolver(
				validator2.ProofsFromContainer(
					container.New(container.WithDelegations(del)),
				),
			),
		)
		require.Error(t, err)
	})

	t.Run("accepts a proof with a NotBefore in the past", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		invoker := testutil.RandomSigner(t)

		del, err := delegation.Delegate(subject, invoker, subject, crankWidget,
			delegation.WithNotBefore(past),
		)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			invoker,
			subject,
			crankWidget,
			ipld.Map{},
			invocation.WithProofs(del.Link()),
		)
		require.NoError(t, err)

		err = validator2.ValidateInvocation(
			t.Context(),
			inv,
			validator2.WithValidationTime(now),
			validator2.WithProofResolver(
				validator2.ProofsFromContainer(
					container.New(container.WithDelegations(del)),
				),
			),
		)
		require.NoError(t, err)
	})

	t.Run("with a policy on a delegation", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		invoker := testutil.RandomSigner(t)

		del, err := delegation.Delegate(subject, invoker, subject, crankWidget,
			delegation.WithPolicyBuilder(policy.Equal(".answer", 42)),
		)
		require.NoError(t, err)

		resolveProof := validator2.ProofsFromContainer(
			container.New(container.WithDelegations(del)),
		)

		t.Run("accepts an invocation whose arguments satisfy the policy", func(t *testing.T) {
			inv, err := invocation.Invoke(
				invoker,
				subject,
				crankWidget,
				ipld.Map{"answer": 42},
				invocation.WithProofs(del.Link()),
			)
			require.NoError(t, err)

			err = validator2.ValidateInvocation(
				t.Context(),
				inv,
				validator2.WithProofResolver(resolveProof),
			)
			require.NoError(t, err)
		})

		t.Run("rejects an invocation whose arguments violate the policy", func(t *testing.T) {
			inv, err := invocation.Invoke(
				invoker,
				subject,
				crankWidget,
				ipld.Map{"answer": 41},
				invocation.WithProofs(del.Link()),
			)
			require.NoError(t, err)

			err = validator2.ValidateInvocation(
				t.Context(),
				inv,
				validator2.WithProofResolver(resolveProof),
			)
			require.Error(t, err)
		})
	})

	t.Run("rejects with incorrect subject in chain", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		alice := testutil.RandomSigner(t)
		bob := testutil.RandomSigner(t)
		unrelatedSubject := testutil.RandomSigner(t)

		del1, err := delegation.Delegate(subject, alice, subject, crankWidget)
		require.NoError(t, err)
		// del2 is about the wrong subject.
		del2, err := delegation.Delegate(alice, bob, unrelatedSubject, crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			bob,
			subject,
			crankWidget,
			ipld.Map{},
			invocation.WithProofs(del1.Link(), del2.Link()),
		)
		require.NoError(t, err)

		err = validator2.ValidateInvocation(
			t.Context(),
			inv,
			validator2.WithProofResolver(
				validator2.ProofsFromContainer(
					container.New(container.WithDelegations(del1, del2)),
				),
			),
		)
		require.Error(t, err)
	})

	t.Run("with non-standard signature in chain", func(t *testing.T) {
		subject := testutil.RandomSigner(t)
		alice := absentee.From(testutil.Must(did.Parse("did:mailto:web.mail:alice"))(t))
		bob := testutil.RandomSigner(t)

		del1, err := delegation.Delegate(subject, alice, subject, crankWidget)
		require.NoError(t, err)
		// del2 is "signed" by alice, who is an absentee signer and produces a
		// non-standard signature.
		del2, err := delegation.Delegate(alice, bob, nil, crankWidget)
		require.NoError(t, err)

		inv, err := invocation.Invoke(
			bob,
			subject,
			crankWidget,
			ipld.Map{},
			invocation.WithProofs(del1.Link(), del2.Link()),
		)
		require.NoError(t, err)

		resolveProof := validator2.ProofsFromContainer(
			container.New(container.WithDelegations(del1, del2)),
		)

		t.Run("rejects by default", func(t *testing.T) {
			err = validator2.ValidateInvocation(
				t.Context(),
				inv,
				validator2.WithProofResolver(resolveProof),
				validator2.WithVerifierResolver(func(ctx context.Context, did did.DID) (ucan.Verifier, error) {
					require.NotEqual(t, "did:mailto:web.mail:alice", did.String(), "shouldn't try to resolve a verifier for a non-standard signature")
					return validator2.ResolveDIDKeyVerifier(ctx, did)
				}),
			)
			require.ErrorContains(t, err, "no non-standard signature verifier configured")
		})

		t.Run("rejects according to non-standard signature verifier", func(t *testing.T) {
			err = validator2.ValidateInvocation(
				t.Context(),
				inv,
				validator2.WithProofResolver(resolveProof),
				validator2.WithNonStandardSignatureVerifier(
					func(ctx context.Context, token ucan.Token, meta ucan.Container) error {
						require.Equal(t, del2.Link(), token.Link(), "should be asked to verify the non-standard signature for the correct token")
						return errors.New("non-standard error failed as expected")
					},
				),
			)
			require.ErrorContains(t, err, "non-standard error failed as expected")
		})

		t.Run("validates according to non-standard signature verifier", func(t *testing.T) {
			err = validator2.ValidateInvocation(
				t.Context(),
				inv,
				validator2.WithProofResolver(resolveProof),
				validator2.WithNonStandardSignatureVerifier(
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

func TestNewProofChainError(t *testing.T) {
	crankWidget := testutil.Must(command.Parse("/widget/crank"))(t)

	t.Run("no prior proofs", func(t *testing.T) {
		sub := testutil.RandomSigner(t)
		eve := testutil.RandomSigner(t)
		mallory := testutil.RandomSigner(t)

		badPrf, err := delegation.Delegate(eve, mallory, eve, crankWidget)
		require.NoError(t, err)

		got := validator2.NewProofChainError(sub, nil, badPrf)
		want := fmt.Sprintf("Proof chain is broken (%s, next proof is %s → %s)",
			sub.DID(), eve.DID(), mallory.DID())
		require.EqualError(t, got, want)
	})

	t.Run("one prior proof", func(t *testing.T) {
		sub := testutil.RandomSigner(t)
		bob := testutil.RandomSigner(t)
		eve := testutil.RandomSigner(t)
		mallory := testutil.RandomSigner(t)

		prf1, err := delegation.Delegate(sub, bob, sub, crankWidget)
		require.NoError(t, err)
		badPrf, err := delegation.Delegate(eve, mallory, eve, crankWidget)
		require.NoError(t, err)

		got := validator2.NewProofChainError(sub, []ucan.Delegation{prf1}, badPrf)
		want := fmt.Sprintf("Proof chain is broken (%s → %s, next proof is %s → %s)",
			sub.DID(), bob.DID(), eve.DID(), mallory.DID())
		require.EqualError(t, got, want)
	})

	t.Run("two prior proofs", func(t *testing.T) {
		sub := testutil.RandomSigner(t)
		bob := testutil.RandomSigner(t)
		carol := testutil.RandomSigner(t)
		eve := testutil.RandomSigner(t)
		mallory := testutil.RandomSigner(t)

		prf1, err := delegation.Delegate(sub, bob, sub, crankWidget)
		require.NoError(t, err)
		prf2, err := delegation.Delegate(bob, carol, sub, crankWidget)
		require.NoError(t, err)
		badPrf, err := delegation.Delegate(eve, mallory, eve, crankWidget)
		require.NoError(t, err)

		got := validator2.NewProofChainError(sub, []ucan.Delegation{prf1, prf2}, badPrf)
		want := fmt.Sprintf("Proof chain is broken (%s → %s → %s, next proof is %s → %s)",
			sub.DID(), bob.DID(), carol.DID(), eve.DID(), mallory.DID())
		require.EqualError(t, got, want)
	})
}

func TestResolveDIDKeyVerifier(t *testing.T) {
	t.Run("ed25519 did:key returns a verifier matching the DID", func(t *testing.T) {
		signer, err := ed25519.Generate()
		require.NoError(t, err)
		d := signer.Verifier().DID()

		v, err := validator2.ResolveDIDKeyVerifier(t.Context(), d)
		require.NoError(t, err)
		require.NotNil(t, v)
		require.Equal(t, d, v.DID())
	})

	t.Run("ed25519 verifier verifies a signature from the corresponding signer", func(t *testing.T) {
		signer, err := ed25519.Generate()
		require.NoError(t, err)
		d := signer.Verifier().DID()

		v, err := validator2.ResolveDIDKeyVerifier(t.Context(), d)
		require.NoError(t, err)
		require.NotNil(t, v)

		msg := []byte("hello, world")
		sig := signer.Sign(msg)

		require.True(t, v.Verify(msg, sig), "verifier should accept a valid signature")

		tampered := []byte("hello, worle")
		require.False(t, v.Verify(tampered, sig), "verifier should reject a signature over a different message")
	})

	t.Run("secp256k1 did:key returns a verifier matching the DID", func(t *testing.T) {
		signer, err := secp256k1.Generate()
		require.NoError(t, err)
		d := signer.Verifier().DID()

		v, err := validator2.ResolveDIDKeyVerifier(t.Context(), d)
		require.NoError(t, err)
		require.NotNil(t, v)
		require.Equal(t, d, v.DID())

		msg := []byte("hello, world")
		sig := signer.Sign(msg)
		require.True(t, v.Verify(msg, sig))
	})

	t.Run("rejects non-did:key DIDs", func(t *testing.T) {
		for _, didStr := range []string{
			"did:web:example.com",
			"did:dns:example.com",
		} {
			t.Run(didStr, func(t *testing.T) {
				d, err := did.Parse(didStr)
				require.NoError(t, err)

				v, err := validator2.ResolveDIDKeyVerifier(t.Context(), d)
				require.Error(t, err)
				require.Nil(t, v)
			})
		}
	})
}
