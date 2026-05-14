package ucan

import (
	"time"

	"github.com/ipfs/go-cid"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/result"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/crypto"
	"github.com/fil-forge/ucantone/ucan/crypto/signature"
	"github.com/fil-forge/ucantone/varsig"
)

// Commands are concrete messages ("verbs") that MUST be unambiguously
// interpretable by the Subject of a UCAN.
//
// Commands MUST be lowercase, and begin with a slash (/). Segments MUST be
// separated by a slash. A trailing slash MUST NOT be present.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#command
type Command = command.Command

// UnixTimestamp is a timestamp in seconds since the Unix epoch.
// Defined as a distinct type so the compiler catches accidental mixing with
// raw int64s carrying other units (e.g. nanoseconds). Construct via [Now] or
// an explicit conversion from a known-seconds value.
type UnixTimestamp int64

// Signer is an entity that can sign UCANs on behalf of a DID.
type Signer interface {
	crypto.Signer

	// DID returns the DID this signer signs on behalf of.
	DID() did.DID

	// SignatureAlgorithm identifies the signature algorithm used by this signer
	// as well as any additional fields needed to configure it.
	SignatureAlgorithm() varsig.SignatureAlgorithm
}

// Signature encapsulates the bytes that comprise the signature as well as the
// details of the signing algorithm and payload encoding.
type Signature interface {
	Header() varsig.VarsigHeader[varsig.SignatureAlgorithm, varsig.PayloadEncoding]
	Bytes() []byte
}

// Verifier is an entity that can verify UCAN signatures against a DID.
type Verifier interface {
	signature.Verifier

	// DID returns the DID this verifier verifies signatures for.
	DID() did.DID
}

type Token interface {
	ipld.Block
	// Issuer DID (sender).
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#issuer--audience
	Issuer() did.DID
	// The subject being invoked.
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#subject
	Subject() did.DID
	// Audience can be conceptualized as the receiver of a postal letter.
	// Returns an undefined DID when no audience is set; check with Defined().
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#issuer--audience
	Audience() did.DID
	// The command to eventually invoke.
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#command
	Command() Command
	// MetadataBytes returns the raw CBOR bytes of the metadata field, or nil
	// if no metadata is present. Decode into a typed cborgen struct directly.
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#metadata
	MetadataBytes() []byte
	// SignedBytes returns the raw CBOR bytes of the SigPayload — the literal
	// bytes the issuer signed over. Verification operates on these directly.
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#envelope
	SignedBytes() []byte
	// A unique, random nonce.
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#nonce
	Nonce() []byte
	// The timestamp at which the invocation becomes invalid.
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#time-bounds
	Expiration() *UnixTimestamp
	// Signature of the UCAN issuer.
	Signature() Signature
}

// Every statement MUST take the form [operator, selector, argument] except for
// connectives (and, or, not) which MUST take the form [operator, argument].
//
// https://github.com/ucan-wg/delegation/blob/main/README.md#policy
type Statement interface {
	Operator() string
	Selector() string
	Argument() any
}

// UCAN Delegation uses predicate logic statements extended with jq-inspired
// selectors as a policy language. Policies are syntactically driven, and
// constrain the args field of an eventual Invocation.
//
// https://github.com/ucan-wg/delegation/blob/main/README.md#policy
type Policy interface {
	Statements() []Statement
}

// A capability is the semantically-relevant claim of a delegation.
//
// https://github.com/ucan-wg/delegation/blob/main/README.md#capability
type Capability interface {
	// The subject that this capability is about.
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#subject
	Subject() did.DID
	// The command of this capability.
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#command
	Command() Command
	// Additional constraints on eventual invocation arguments, expressed in the
	// UCAN Policy Language.
	//
	// https://github.com/ucan-wg/delegation/blob/main/README.md#policy
	Policy() Policy
}

// UCAN Delegation is a delegable certificate capability system with
// runtime-extensibility, ad-hoc conditions, cacheability, and focused on ease
// of use and interoperability. Delegations act as a proofs for UCAN
// invocations.
//
// https://github.com/ucan-wg/delegation/blob/main/README.md
type Delegation interface {
	Capability
	Token
	// NotBefore is the time in seconds since the Unix epoch that the UCAN
	// becomes valid.
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#time-bounds
	NotBefore() *UnixTimestamp
}

// A Task is the subset of Invocation fields that uniquely determine the work to
// be performed.
//
// https://github.com/ucan-wg/invocation/blob/main/README.md#task
type Task interface {
	ipld.Block
	// A concrete, dispatchable message that can be sent to the Executor.
	//
	// https://github.com/ucan-wg/invocation/blob/main/README.md#command
	Command() Command
	// The subject being invoked.
	//
	// https://github.com/ucan-wg/invocation/blob/main/README.md#subject
	Subject() did.DID
	// ArgumentsBytes returns the raw CBOR bytes of the args field. Decode
	// into a typed cborgen struct directly:
	//
	//	var args MyArgs
	//	err := args.UnmarshalCBOR(bytes.NewReader(t.ArgumentsBytes()))
	//
	// https://github.com/ucan-wg/invocation/blob/main/README.md#arguments
	ArgumentsBytes() []byte
	// A unique, random nonce. It ensures that multiple (non-idempotent)
	// invocations are unique. The nonce SHOULD be empty (0x) for commands that
	// are idempotent (such as deterministic Wasm modules or standards-abiding
	// HTTP PUT requests).
	//
	// https://github.com/ucan-wg/invocation/blob/main/README.md#nonce
	Nonce() []byte
}

// UCAN Invocation defines a format for expressing the intention to execute
// delegated UCAN capabilities, and the attested receipts from an execution.
//
// https://github.com/ucan-wg/invocation/blob/main/README.md
type Invocation interface {
	Task
	Token
	// Task returns an object containing just the fields that comprise the task
	// for the invocation.
	//
	// https://github.com/ucan-wg/invocation/blob/main/README.md#task
	Task() Task
	// Delegations that prove the chain of authority.
	//
	// https://github.com/ucan-wg/invocation/blob/main/README.md#proofs
	Proofs() []cid.Cid
	// The timestamp at which the invocation was created.
	//
	// https://github.com/ucan-wg/invocation/blob/main/README.md#issued-at
	IssuedAt() *UnixTimestamp
	// CID of the receipt that enqueued the Task.
	//
	// https://github.com/ucan-wg/invocation/blob/main/README.md#cause
	Cause() *cid.Cid
}

// Receipt is a signed assertion by an executor that a task ran and produced a
// particular result.
//
// On the wire a receipt is a /ucan/assert/receipt invocation (per the UCAN WG
// draft, ucan-wg/receipt#1). At the Go level, however, Receipt is its own
// type — it does not embed Invocation — so the interface exposes only what is
// meaningful for a receipt. Receipt-shaped accessors for proofs and
// expiration will be added once those semantics settle in the spec.
type Receipt interface {
	ipld.Block

	// Issuer is the DID of the executor that signed this attestation.
	Issuer() did.DID
	// Ran is the CID of the executed task the receipt is for.
	Ran() cid.Cid
	// Out is the attested result of the execution of the task. The Result's
	// Ok and Err branches hold raw CBOR bytes; consumers decode into the
	// typed cborgen struct that matches the task's expected output.
	Out() result.Result[[]byte, []byte]
	// IssuedAt is the timestamp the executor signed at, or nil if unset.
	IssuedAt() *UnixTimestamp
	// Nonce is the receipt's nonce.
	Nonce() []byte
	// MetadataBytes returns the raw CBOR bytes of the meta field, or nil if
	// metadata is not set.
	MetadataBytes() []byte
	// SignedBytes returns the raw CBOR bytes of the SigPayload — the bytes the
	// issuer signed over.
	SignedBytes() []byte
	// Signature of the executor.
	Signature() Signature
}

// Container is a format for transmitting one or more UCAN tokens as bytes,
// regardless of the transport.
//
// https://github.com/ucan-wg/container/blob/main/Readme.md
type Container interface {
	// Invocations the container contains.
	Invocations() []Invocation
	// Delegations the container contains.
	Delegations() []Delegation
	// Delegation retrieves a delegation from the container by it's CID.
	Delegation(cid.Cid) (Delegation, bool)
	// Receipts the container contains.
	Receipts() []Receipt
	// Receipt retrieves a receipt from the container by the CID of a [Task] that
	// was executed.
	Receipt(cid.Cid) (Receipt, bool)
}

// IsExpired checks if a UCAN is expired.
func IsExpired(ucan Token) bool {
	exp := ucan.Expiration()
	if exp == nil {
		return false
	}
	return *exp <= Now()
}

// IsTooEarly checks if a delegation is not active yet.
func IsTooEarly(delegation Delegation) bool {
	nbf := delegation.NotBefore()
	if nbf == nil {
		return false
	}
	return *nbf != 0 && Now() <= *nbf
}

// Now returns a  Unix timestamp for comparing it against time window of the
// UCAN.
func Now() UnixTimestamp {
	return UnixTimestamp(time.Now().Unix())
}
