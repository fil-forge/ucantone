# Note: `*big.Int` support in `datamodel.Any` (coordinate with the policy spike)

Heads-up for whoever is working the typed-policy spike. A separate fix landed in
`ipld/datamodel/any.go` to make `Any` understand CBOR bignums. It overlaps the
same "datamodel is stricter than the types flowing through it" theme this spike
addresses, so the two need to stay consistent.

## The original problem

The `piri-signing-service` UCAN migration uses libforge's `pdp/sign` capability
arguments, whose ID fields are `*big.Int`:

```go
DataSet *big.Int  // /pdp/sign/dataset/{create,delete}
Nonce   *big.Int  // /pdp/sign/pieces/add
Pieces  []*big.Int // /pdp/sign/pieces/remove/schedule
```

cbor-gen encodes `*big.Int` as a **CBOR bignum: tag 2 + byte string**
(`cbor-gen/gen.go:931-966`). Every server invocation failed validation with:

```
decoding invocation arguments for capability check: unmarshaling map value
for key "dataSet": unsupported CBOR type: 6
```

### Why it happened

`validator.Authorize` (`validator/validator.go:56-60`) decodes the raw argument
bytes into a schema-less `datamodel.Map` *before* running `cap.Allows`:

```go
var mapArgs datamodel.Map
err = mapArgs.UnmarshalCBOR(bytes.NewReader(inv.ArgumentsBytes()))
```

`Map` decodes each value via `Any.UnmarshalCBOR`, whose `MajTag` switch only
knew tag 42 (CID). A bignum is tag 2 (major type 6) → `unsupported CBOR type: 6`.

Key point: the failure is a **decode** error that fires **before** any policy
matching runs. It is *not* the marshal/`DeepEqual` bug this spike targets — but
it lives in the same `Any` type.

## The fix that landed

In `ipld/datamodel/any.go` (currently only in the local `../ucantone` replace
copy — **must be upstreamed + version-bumped**):

- **Decode**: added `case 2` to the `MajTag` switch — consumes the tag-2 header,
  reads the inner byte string (≤256 bytes, cbor-gen's cap), yields
  `new(big.Int).SetBytes(b)`.
- **Encode**: added `*big.Int` / `big.Int` cases (`marshalCborBigInt`) writing
  tag 2 + byte string, rejecting negatives — mirrors cbor-gen so values
  round-trip.
- `Any.Value` can now hold a `*big.Int`. DagJSON paths were intentionally **not**
  touched (DAG-JSON numbers are f64; encoding a large bignum there would lose
  data — needs a deliberate representation decision).

## What the spike must account for

1. **`canonicalize` has no bignum arm.** Its kind set is
   `nil | bool | int64 | string | []byte | cid.Cid | []any | map[string]any`,
   and it explicitly rejects `uint64 > MaxInt64` ("IPLD has no uint64").
   `big.Int` is a struct, so a `*big.Int` literal (or the `*big.Int` the selector
   now decodes out of arguments) hits the `reflect.Pointer` → `reflect.Struct`
   fall-through → `unsupported type for IPLD value: *big.Int`.
   - If any typed policy ever constrains `dataSet` / `nonce` / `pieces`, add a
     `*big.Int` (and probably `big.Int`) case to `canonicalize` that returns the
     `*big.Int` as-is (or a normalized copy), consistent with how `Any` now
     stores it.

2. **`MatchStatement` uses `reflect.DeepEqual` on `*big.Int`.** Two `*big.Int`
   that are numerically equal but distinct pointers are **not** `DeepEqual`-equal
   in general (different internal `nat` backing arrays / capacities). A bignum
   constraint would silently never match — the exact failure mode the spike's
   DESIGN doc calls out for `multihash.Multihash`. Matching on bignums needs a
   value comparison (`(*big.Int).Cmp`), not `DeepEqual`.

3. **No policy currently constrains these fields**, so neither of the above is
   exercised today — the decode fix alone unblocks the signing-service tests.
   But the moment the typed builders are used to bind a `*big.Int` field, both
   gaps become live. Worth folding a bignum case into `canonicalize` + match in
   the same pass as the spike so `Any` (decode/encode) and policy (canonicalize/
   compare) agree end to end.

## TL;DR

`Any` now supports `*big.Int` over CBOR. The spike's `canonicalize` and
`reflect.DeepEqual`-based matching do **not** yet — same class of bug as the
`multihash.Multihash` case, just for the Integer-bignum kind. Keep them in sync
and land the `Any` change upstream rather than relying on the `replace`.
