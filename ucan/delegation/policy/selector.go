package policy

// Typed, code-generated policy authoring.
//
// A [Selector] is a jq selector path (".blob.digest") paired, at the type
// level, with the Go type of the value at that path. Field-descriptor values
// holding selectors are produced by the descriptor generator (see the
// fieldgen package) from a command's argument struct, so:
//
//	pol, err := policy.Build(
//		policy.Eq(RetrieveArgsFields.Blob.Digest, digest),   // value pinned to multihash.Multihash
//		policy.Gte(RetrieveArgsFields.Blob.Size, uint64(0)),
//		policy.Each(ManifestFields.Shards, func(s ShardFields) []policy.StatementBuilderFunc {
//			return []policy.StatementBuilderFunc{policy.Eq(s.Codec, uint64(0x55))}
//		}),
//	)
//
// The comparison value is type-checked against the field type by the compiler,
// and the selector path cannot be mistyped because it is generated from a real
// field. The builders ([Eq], [Gte], [Glob], [Each], ...) return the same
// [StatementBuilderFunc] as the legacy string-selector builders, so they drop
// straight into [Build] / delegation.WithPolicyBuilder and share the matcher
// and wire format unchanged.

// Selector is a jq selector path into an argument value, carrying — at the type
// level only — the Go type T of the value found at that path. T pins the value
// type accepted by the comparison builders ([Eq], [Gt], ...).
type Selector[T any] struct {
	path string
}

// NewSelector constructs a [Selector] for the given jq path. It is called by
// generated descriptor code; hand-written callers normally reference a
// generated descriptor instead.
func NewSelector[T any](path string) Selector[T] {
	return Selector[T]{path: path}
}

// Path returns the jq selector path.
func (s Selector[T]) Path() string { return s.path }

// SliceSelector is a [Selector] at a list-valued path, paired with the
// descriptor of its elements. E is the element descriptor type: a generated
// *Fields struct for struct elements (its selector paths are relative to an
// element), or a [Selector] of the element type for scalar elements (whose
// path is the identity selector "."). The element descriptor is handed to the
// closure passed to [Each] / [Some].
type SliceSelector[E any] struct {
	path string
	elem E
}

// NewSliceSelector constructs a [SliceSelector] for the given list path and
// element descriptor. It is called by generated descriptor code.
func NewSliceSelector[E any](path string, elem E) SliceSelector[E] {
	return SliceSelector[E]{path: path, elem: elem}
}

// Path returns the jq selector path of the list.
func (s SliceSelector[E]) Path() string { return s.path }

// Elem returns the element descriptor (with element-relative selector paths).
func (s SliceSelector[E]) Elem() E { return s.elem }

// MapSelector is a [Selector] at a map-valued path, paired with the descriptor
// of its values, used by [Each] / [Some] to quantify over the map's values.
type MapSelector[E any] struct {
	path string
	elem E
}

// NewMapSelector constructs a [MapSelector] for the given map path and value
// descriptor. It is called by generated descriptor code.
func NewMapSelector[E any](path string, elem E) MapSelector[E] {
	return MapSelector[E]{path: path, elem: elem}
}

// Path returns the jq selector path of the map.
func (s MapSelector[E]) Path() string { return s.path }

// Elem returns the value descriptor (with value-relative selector paths).
func (s MapSelector[E]) Elem() E { return s.elem }
