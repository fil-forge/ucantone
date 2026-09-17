# ucantone

Go implementation of UCAN 1.0: delegations, invocations, receipts, promises
and containers, with the DID methods, varsig headers and multikey signers
they need, an HTTP client/server runtime for executing invocations, and typed
command bindings on top. It is a library: applications and higher-level
libraries define their own commands and capabilities with it, and many of
them depend on it directly. Its only dependencies are third-party modules
(multiformats, go-cid, cbor-gen, dag-json-gen, secp256k1). Keep it that way.

Module: `github.com/fil-forge/ucantone` (Go 1.27). API docs:
[pkg.go.dev/github.com/fil-forge/ucantone](https://pkg.go.dev/github.com/fil-forge/ucantone).

## The model in five lines

- A UCAN is a signed varsig envelope `[signature, {h, "<tag>": payload}]`,
  DAG-CBOR encoded and addressed by CIDv1. The payload tag
  (`ucan/dlg@1.0.0-rc.1`, `ucan/inv@…`) selects the variant; `sub` is the
  root of authority, `cmd` a slash path where `/db` proves `/db/write`, `pol`
  a predicate list over the invocation's `args`.
- A proof chain is valid when each link's `iss` is the previous `aud`
  (principal alignment), `sub` never changes (subject stability, except
  powerline delegations with `sub: null`, which re-bind to the subject above
  them), and `cmd`/`pol`/`exp`/`nbf` only narrow (attenuation). The validator
  reports each as its own error (`PrincipalAlignment`, `SubjectAlignment`,
  `Attenuation`, `Expired`, `TooEarly`).
- The **task** is the CID of `{sub, cmd, args, nonce}`: no issuer, proofs,
  expiry or signature. It is the stable handle for the work; receipts (`ran`)
  and promises (`await/ok`, `await/error`, `await/*`) reference it. Same
  task with the same nonce means the same work, so `WithNoNonce()` makes an
  idempotent invocation memoizable.
- A receipt is an invocation of `/ucan/assert/receipt` issued by the
  executor, with `ran` (task CID) and `out` (`ok` or `error`) as arguments.
- Revocation checking is not implemented here (issue #13).

## Commands

- Standard loop: `go build ./... && go vet ./... && go test ./...`.
- `make ci` is what CI enforces: `build`, `codegen-build` (compiles the
  generators under the `codegen` tag), `gen-check` (regenerates and fails on a
  diff) and `test`. Run it before opening a PR. CI also runs the shared
  Unified CI `go-check`/`go-test` workflows (codecov).
- `make gen` after editing any struct in a `datamodel` package. Never
  hand-edit `*_gen*.go`.
- `make cover` opens an HTML coverage report.
- If the checkout sits inside a Go workspace (a `go.work` in a parent
  directory), plain `go` commands run in workspace mode; `GOWORK=off go test
  ./...` tests the module standalone, the way CI does.
- `staticcheck ./...` is configured per package (`staticcheck.conf` in each
  `datamodel` package disables ST1005 for generated code).
- Tests use `testify` (`require`/`assert`) and the `testutil` helpers
  (`RandomIssuer`, `RandomDID`, `RandomCID`, `Must(...)(t)`). Table-driven
  with `t.Run` is the norm. Everything runs without Docker or network.

## Layout

The public package for each token type wraps a `datamodel` subpackage that
holds the wire structs and their generated codecs.

- `ucan/` — the interfaces everything else implements: `Principal`, `Signer`,
  `Issuer`, `Verifier`, `Token`, `Delegation`, `Invocation`, `Task`,
  `Receipt`, `Container`, `Policy`, `Capability`, `UnixTimestamp`.
  - `command/` — slash-separated command paths (`/msg/send`), `Proves`.
  - `delegation/` (+ `policy/`, `policy/selector/`) — `Delegate`, policy
    builders (`Equal`, `Like`, `All`, `Any`, `And`, `Or`, `Not`, …), the
    selector language and policy matching.
  - `invocation/` — `Invoke` (typed args) / `InvokeMap`, `Task`.
  - `receipt/` — `IssueOK`/`IssueErr`. A receipt is an invocation of
    `/ucan/assert/receipt` issued by the executor with no audience.
  - `promise/` — `AwaitOK`/`AwaitError`/`AwaitAny` for pipelining.
  - `container/` — bundles tokens; `Encode(codec, ct)` with the
    `Raw`/`Base64`/`Base64url` (+`Gzip`) codecs; `Decode` sniffs the codec.
    `MaxTokens` caps the token count; encode and decode fail beyond it, so
    callers building large containers budget against it up front.
  - `envelope/`, `token/`, `nonce/`, `crypto/` — shared envelope model and
    helpers.
- `validator/` — `ValidateInvocation`/`ValidateToken`: signature
  verification via DID resolution, proof-chain walk, attenuation and policy
  checks, time bounds. Options: `WithProofResolver`, `WithDIDResolver`,
  `WithVerifierFactories`, `WithValidationTime`,
  `WithNonStandardSignatureVerifier`. Typed failures in `validator/errors`.
- `execution/` — `Request`/`Response`/`Executor`/`HandlerFunc` for a single
  invocation; `dispatcher/` routes a validated invocation to the handler for
  its command and issues the receipt; `batch/` — `Request`/`Response`/
  `Executor` (`ExecuteBatch`) for many invocations in one round trip, with
  receipts looked up by task CID.
- `server/` — `NewHTTP(issuer)` is an `http.Handler` (and `RoundTripper`, for
  in-process tests) over a dispatcher; its `ExecuteBatch` runs every
  invocation addressed to it. `client/` — `NewHTTP(url)`; `ExecuteBatch` is
  the primitive and `Execute` a batch of one; `client.New(transport, codec)`
  for other transports. `transport/` — the inbound/outbound codec interfaces;
  HTTP bodies are DAG-CBOR containers.
- `binding/` — `Bind[Args, OK](cmd)`: one typed definition of a command that
  gives you `Invoke`, `Delegate`, `Route`/`Handler` and `Unpack`. Downstream
  libraries define their commands with it.
- `did/` — `DID` (string form; `Parse`/`MustParse`), `Document`,
  verification methods and relationships, `Resolver`. Methods: `key/`,
  `web/`, `plc/` (has its own README; also a directory client for
  creating/updating PLC DIDs). `resolver/` composes resolvers: `ByMethod`,
  `Tiered`, `Cached`, `WellKnown`.
- `multikey/` — signers/verifiers as multiformats-tagged key bytes;
  `ed25519/`, `secp256k1/`, `mldsa44/` (post-quantum). `KeyIssuer` derives a
  `did:key` issuer from a signer; `FormatSigner`/`FormatVerifier` for
  multibase strings.
- `varsig/` — signature header codec (own README); `algorithm/{eddsa,ecdsa,
  mldsa,nonstandard}`. `prev/` is an earlier draft of the codec with no
  callers in this repo.
- `absentee/` — an `Issuer` that emits an empty signature with the
  `nonstandard` algorithm; the verifier must confirm authorization out of
  band (`WithNonStandardSignatureVerifier`).
- `ipld/` — `Map`/`Any`/`Block`; `datamodel/` has `Any`, `Map`, `Raw`
  (opaque CBOR bytes); `codec/{dagcbor,dagjson}` content types.
- `result/` — `Result[OK, Err]`. `errors/` — `Named` errors and the
  `ErrorModel` that travels in receipts.
- `testutil/` — randomised principals, args and helpers for tests here and in
  dependents. `examples/` — runnable examples (`go test ./examples`); the
  README snippets are copied from them, keep both in step.
- `notes.md` — design decisions and intentional divergences from the spec
  text. Add to it when you make another one.

## Conventions

- **Accept interfaces, return concrete types.** Functions take
  `ucan.Delegation`, `ucan.Issuer`, `ipld.Map`; constructors return
  `*delegation.Delegation`, `*invocation.Invocation`, etc.
- **Functional options** on every constructor: `With…` in an `options.go`
  next to the type. Add new knobs there; do not add parameters.
- **Serialization is cbor-gen + dag-json-gen, not go-ipld-prime.** Each
  `datamodel` package has a `gen/main.go` (`//go:build codegen`,
  `//go:generate go run -tags codegen .`) listing its models and writing
  `cbor_gen*.go` / `dag_json_gen*.go` tagged `//go:build !codegen`. Most
  models are map-encoded; the envelope and policy statements are
  tuple-encoded (`WriteTupleEncodersToFile`). Wire structs carry a `Model`
  suffix and a version where the spec does (`TokenPayloadModel1_0_0_rc1`).
  Use `datamodel.Raw` for fields that must round-trip opaque CBOR (arguments,
  receipt `out`) and `datamodel.Any` for dynamic values. Every type gets both
  CBOR and DAG-JSON codecs; DAG-JSON exists so tokens can be read and diffed.
- **Links are `cid.Cid`**, never an `ipld.Link` interface. DIDs are stored in
  their string form; `did.DID` has CBOR/JSON/DAG-JSON marshalers.
- **Signatures are raw bytes.** The algorithm lives in the varsig header.
  Key types are split so verifiers can be imported without signing code:
  `multikey/<name>/verifier` registers its multicodec with
  `multikey.Register` in `init()` and imports the `varsig/algorithm/<scheme>`
  package that registers the algorithm; `multikey/<name>` adds the signer.
  Registration is by side effect, so import the package you need (the mldsa44
  verifier test shows the pattern and checks it).
- **Never format a signer with `%s`/`%v`.** Multikey signers are private key
  bytes; print `signer.DID()` or `multikey.FormatVerifier(...)`. Do not log
  or write key material anywhere.
- **Errors that cross the wire are `ErrorModel`s.** Construct them with the
  helpers in `validator/errors`, `execution`, `binding` and
  `errors.New(name, msg)` so they carry a stable `name`; handlers return them
  through `res.SetFailure(err)`.
- **Two CIDs per invocation.** `inv.Link()` is the signed envelope;
  `inv.Task().Link()` is the task (`{sub, cmd, args, nonce}`). Receipts
  (`Ran`), promises and `Cause` reference the task link. Both are `cid.Cid`,
  so the compiler will not catch a mix-up (issue #24).
- **Container order is not preserved.** `container.Encode` sorts tokens
  bytewise for determinism; look tokens up by CID (`Delegation(cid)`,
  `Receipt(cid)`) rather than by position, and keep `prf` ordering in the
  invocation itself (issue #29).
- **Spec fixtures are tests.** `ucan/delegation/testdata`,
  `ucan/delegation/policy/internal/fixtures` and `…/selector/internal/fixtures`
  are the `ucan-wg/spec` 1.0.0 fixtures (policy.json has non-integer numbers
  removed; see its README). `validator/internal/fixtures/invocations.json` is
  generated by `go run ./validator/internal > validator/internal/fixtures/invocations.json`
  with fixed keys and timestamps; regenerate it when validation rules change,
  do not edit it by hand.
- **Terminology.** Delegations are *issued* (never minted) and *attenuated*
  when re-delegated; an invocation is *executed*; the party that executes is
  the *executor* and issues the *receipt*; `sub` is the *root of authority*;
  a `sub: null` delegation is a *powerline*. Commands are slash paths. The
  library is "ucantone" (lower case).

## Specs and downstream

- Normative sources are the `ucan-wg` specs (spec, delegation, invocation,
  receipt, revocation, promise, container) and ChainAgnostic varsig. When
  code and spec disagree, follow the code and flag it.
- **Blast radius.** This is a dependency of other libraries and services,
  which pin it by version and pick up changes only on `go get -u`. Treat any
  change to a wire model, a `ucan/` interface, or an exported signature as a
  breaking change: prefer adding an option or a new function to changing an
  existing one, and check the dependents you know of before merging.
- This repo owns the UCAN primitives. Application-specific commands,
  capabilities and receipt types belong in the libraries and services that
  consume ucantone, not here.
