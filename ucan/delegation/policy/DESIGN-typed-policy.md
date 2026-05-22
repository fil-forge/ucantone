# Typed, struct-bound policy builders (spike)

A spike adding a stronger-typed authoring API to `ucan/delegation/policy`,
motivated by `piri-pdp .../access/grant.go:212`, where the generic
`policy.Equal(".blob.digest", value any)` forced a `[]byte(digest)` cast and a
five-line comment to explain why.

The typed builders **coexist** with the legacy string-selector builders
(`Equal`, `And`, `Like`, …) in the same package and reuse the same operator
constants, wire model, and matcher. Nothing on the wire changes.

## The bug it removes

The cast was load-bearing for **two** reasons, both rooted in the same flaw:
the policy layer never lowered a literal to its canonical IPLD form.

1. **Serialization.** `datamodel.Any` dispatches on *exact* type (`case []byte:`),
   so a named `multihash.Multihash` fell through to the reflection path and
   marshalled element-by-element → `"unsupported type: uint8"`.
2. **Matching (silent).** `MatchStatement` compares with `reflect.DeepEqual`,
   which is type-identity sensitive. A `multihash.Multihash` literal would
   never equal the plain `[]byte` the selector decodes — so even a "successful"
   policy would never match.

### Fix: `canonicalize` (`canonicalize.go`)

Lowers any Go value to the canonical IPLD kind set
(`nil | bool | int64 | string | []byte | cid.Cid | []any | map[string]any`) by
dispatching on `reflect.Kind`, so named types (`multihash.Multihash` ~ `[]byte`,
a `Size` ~ `uint64`) are handled transparently. Applied at build time in every
typed constraint, and in `match.go`'s `normalize` so the decoded side matches.
This is the base layer the builders sit on.

## The builder (`bind.go`, `constraint.go`)

Hold an instance of the argument struct, point at fields, let `Bind` resolve
addresses → selector paths by walking the struct's `cborgen` tags. The path
cannot be mistyped (it's a real field) and the value is type-checked against
the field by the compiler. No code generation.

```go
var a blob.RetrieveArguments
pol, err := policy.Bind(&a,
    policy.Eq(&a.Blob.Digest, digest),    // T inferred = multihash.Multihash
    policy.Gte(&a.Blob.Size, uint64(0)),
    policy.AnyOf(
        policy.Eq(&a.Blob.Size, uint64(0)),
        policy.Gt(&a.Blob.Size, uint64(1024)),
    ),
    policy.Each(&a.Shards, func(s *blob.Shard) []policy.Constraint {
        return []policy.Constraint{policy.Eq(&s.Codec, uint64(0x55))}
    }),
)
```

### Operator coverage (full spec)

| Spec op | Legacy | Typed | Shape |
|---|---|---|---|
| `== != < <= > >=` | `Equal`/… | `Eq Ne Lt Lte Gt Gte` | `(&a.X, v)` |
| `like` | `Like` | `Glob` | `(&a.X, "p*")` |
| `and` | `And` | `AllOf` | `(c, …)` |
| `or` | `Or` | `AnyOf` | `(c, …)` |
| `not` | `Not` | `Negate` | `(c)` |
| `all` | `All` | `Each` / `EachMap` | `(&a.Xs, func(x) []Constraint)` |
| `any` | `Any` | `Some` / `SomeMap` | `(&a.Xs, func(x) []Constraint)` |

Typed verbs are renamed only where they would collide with the legacy package
funcs; a real change could supersede the legacy set.

### How resolution works

`Bind` walks the subject once into an `address → selector` map
(`fieldPaths`), then `buildModel` recurses the constraint tree to the wire
`StatementModel`:

- **leaf / connective / negation** — children point at the *same* subject, so
  they resolve against the same map.
- **quantifier** — the collection field (`&a.Shards`) resolves against the
  subject for its selector (`.shards`); the element constraints reference a
  *fresh* element instance the builder allocates, walked separately so their
  selectors are relative (`.codec`). Multiple element constraints collapse into
  an implicit `and`, matching the single-inner-statement shape of all/any.

A field pointer that doesn't belong to the bound subject is a hard error, not a
silent mismatch (`TestBind_ForeignPointer`).

## grant.go, before / after

```go
// before
delegation.WithPolicyBuilder(policy.Equal(".blob.digest", []byte(digest)))

// after
var a blob.RetrieveArguments
pol, _ := policy.Bind(&a, policy.Eq(&a.Blob.Digest, digest))
delegation.WithPolicy(pol)
```

Natural next step: `bind.Binding[A, O]` already pins the argument type `A`, so a
`Binding.PolicyFor(func(a *A) []policy.Constraint)` helper would scope the
builder to exactly the right struct without the caller naming the type twice.

## Tests

`bind_test.go` uses fixtures mirroring the libforge `blob` structs (same
`cborgen` tags), covering comparisons, glob, and/or/not, all/any quantifiers
(including a multi-constraint element group), and the foreign-pointer error —
each asserting both the built statement shape and that `Match` accepts/rejects
decoded args correctly.

## Bignums (`*big.Int`) — coordinated with `datamodel.Any`

See `NOTE-bigint-datamodel.md`: a CBOR-bignum fix landed in `datamodel.Any`
(decode/encode of tag-2 bignums) for libforge's `pdp/sign` args, whose IDs are
`*big.Int`. That is the *same* class of "datamodel is stricter / DeepEqual is
identity-sensitive" bug this spike targets, so the policy layer now handles
bignums end to end:

- **`canonicalize`** accepts `*big.Int`/`big.Int`: values that fit int64
  collapse to int64 (common path, and so a small bignum equals an int64-encoded
  peer); larger magnitudes are kept as `*big.Int`. A `uint64` that overflows
  int64 now promotes to `*big.Int` instead of erroring.
- **Matching** compares integers by value: `valuesEqual` and `isOrdered`
  promote both sides through `asBigInt` and use `(*big.Int).Cmp`, so a bignum
  no longer silently never-matches (the multihash trap, for integers). List/map
  equality recurses through the same rule.
- **Dependency:** serializing a policy whose literal exceeds int64 relies on the
  `Any` bignum *encode* change; that must be upstreamed + version-bumped rather
  than left in the local `replace` (per the note). Policy-level matching is
  tested here without needing the wire round-trip.

## Open edges

- **Maps in quantifiers** are supported via `EachMap`/`SomeMap`; nested
  quantifiers work through the same recursion.
- **Quantifiers over scalar elements.** `Each`/`Some` constrain *fields* of a
  struct element, so a `[]*big.Int` or `[]string` (elements with no fields)
  can't yet be constrained by element *value* — the legacy `All`/`Any` with an
  identity selector still can. Needs a value-constraint form for the element.
- **Pointer fields.** `fieldPaths` records the pointer field's address and
  recurses through non-nil pointers; constraining *through* a nil pointer field
  is not yet exercised.
- **DAG-JSON bignums.** `Any`'s bignum support is CBOR-only (DAG-JSON numbers
  are f64); a policy literal exceeding int64 has no lossless DAG-JSON form yet.
- **Naming.** `Glob`/`AllOf`/`AnyOf`/`Negate`/`Each`/`Some` avoid colliding with
  the legacy builders; superseding them would free the shorter names.
