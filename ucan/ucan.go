package ucan

import (
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/result"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/crypto"
	"github.com/fil-forge/ucantone/ucan/crypto/signature"
	"github.com/fil-forge/ucantone/varsig"
	"github.com/ipfs/go-cid"
)

// The Principal who's authority is delegated or invoked. A Subject represents
// the Agent that a capability is for. A Subject MUST be referenced by DID.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#subject
type Subject = Principal

// Commands are concrete messages ("verbs") that MUST be unambiguously
// interpretable by the Subject of a UCAN.
//
// Commands MUST be lowercase, and begin with a slash (/). Segments MUST be
// separated by a slash. A trailing slash MUST NOT be present.
//
// https://github.com/ucan-wg/spec/blob/main/README.md#command
type Command = command.Command

// Principal is a DID object representation with a `did` accessor for the DID.
type Principal interface {
	DID() did.DID
}

// UTCUnixTimestamp is a timestamp in seconds since the Unix epoch.
type UTCUnixTimestamp = uint64

// https://github.com/ucan-wg/spec/blob/main/README.md#nonce
type Nonce = []byte

// Signer is an entity that can sign UCANs with keys from a `Principal`.
type Signer interface {
	Principal
	crypto.Signer

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

// Verifier is an entity that can verify UCAN signatures against a `Principal`.
type Verifier interface {
	Principal
	signature.Verifier
}

// Link is an IPLD link to a UCAN token.
type Link = cid.Cid

type Token interface {
	ipld.Block
	// Issuer DID (sender).
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#issuer--audience
	Issuer() Principal
	// The subject being invoked.
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#subject
	Subject() Principal
	// Audience can be conceptualized as the receiver of a postal letter.
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#issuer--audience
	Audience() Principal
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
	Nonce() Nonce
	// The timestamp at which the invocation becomes invalid.
	//
	// https://github.com/ucan-wg/spec/blob/main/README.md#time-bounds
	Expiration() *UTCUnixTimestamp
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
	Subject() Principal
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
	NotBefore() *UTCUnixTimestamp
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
	Subject() Principal
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
	Nonce() Nonce
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
	Proofs() []Link
	// The timestamp at which the invocation was created.
	//
	// https://github.com/ucan-wg/invocation/blob/main/README.md#issued-at
	IssuedAt() *UTCUnixTimestamp
	// CID of the receipt that enqueued the Task.
	//
	// https://github.com/ucan-wg/invocation/blob/main/README.md#cause
	Cause() *Link
}

// UCAN Invocation Receipt is a signed assertion of the executor state
// describing the result and effects of the invocation.
type Receipt interface {
	Token
	Invocation
	// Ran is the CID of the executed task the receipt is for.
	Ran() cid.Cid
	// Out is the attested result of the execution of the task. The Result's
	// Ok and Err branches hold raw CBOR bytes; consumers decode into the
	// typed cborgen struct that matches the task's expected output.
	Out() result.Result[[]byte, []byte]
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
	Delegation(Link) (Delegation, bool)
	// Receipts the container contains.
	Receipts() []Receipt
	// Receipt retrieves a receipt from the container by the CID of a [Task] that
	// was executed.
	Receipt(Link) (Receipt, bool)
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

// Now returns a UTC Unix timestamp for comparing it against time window of the
// UCAN.
func Now() UTCUnixTimestamp {
	return UTCUnixTimestamp(time.Now().Unix())
}
