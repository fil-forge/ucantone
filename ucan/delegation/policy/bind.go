package policy

import (
	"fmt"
	"math/big"

	"github.com/fil-forge/ucantone/ipld/datamodel"
	pdm "github.com/fil-forge/ucantone/ucan/delegation/policy/datamodel"
)

// Typed policy builders. These mirror the legacy string-selector builders
// ([Equal], [Like], [All], ...) but take a generated [Selector] instead of a
// raw jq string, so the comparison value is type-checked against the field and
// the selector path is generated from a real field. They return the same
// [StatementBuilderFunc] and produce the same wire model, so the matcher and
// serialization are unchanged.

// Ordered is the set of field types the ordered comparison builders
// ([Gt], [Gte], [Lt], [Lte]) accept: exactly the types the matcher knows how
// to order — the integer kinds, string (lexicographic), and big integers
// (int64/CBOR-bignum). Float kinds are intentionally excluded: the matcher
// does not order them and neither the CBOR nor the DAG-JSON codec represents
// them, so ordering a float field is a compile error rather than a value that
// silently never matches.
type Ordered interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~string | big.Int | *big.Int
}

// --- leaf comparisons -------------------------------------------------------

// Eq constrains the selected field to equal value (==).
func Eq[T any](s Selector[T], value T) StatementBuilderFunc {
	return comparison(OpEqual, s.path, value)
}

// Ne constrains the selected field to differ from value (!=).
func Ne[T any](s Selector[T], value T) StatementBuilderFunc {
	return comparison(OpNotEqual, s.path, value)
}

// Gt constrains the selected field to be greater than value (>).
func Gt[T Ordered](s Selector[T], value T) StatementBuilderFunc {
	return comparison(OpGreaterThan, s.path, value)
}

// Gte constrains the selected field to be greater than or equal to value (>=).
func Gte[T Ordered](s Selector[T], value T) StatementBuilderFunc {
	return comparison(OpGreaterThanOrEqual, s.path, value)
}

// Lt constrains the selected field to be less than value (<).
func Lt[T Ordered](s Selector[T], value T) StatementBuilderFunc {
	return comparison(OpLessThan, s.path, value)
}

// Lte constrains the selected field to be less than or equal to value (<=).
func Lte[T Ordered](s Selector[T], value T) StatementBuilderFunc {
	return comparison(OpLessThanOrEqual, s.path, value)
}

func comparison[T any](op, path string, value T) StatementBuilderFunc {
	return func() (Statement, error) {
		cv, err := canonicalize(value)
		if err != nil {
			return Statement{}, fmt.Errorf("canonicalizing %q value: %w", op, err)
		}
		return newStatement(pdm.StatementModel{
			Op:       op,
			Selector: path,
			Value:    &datamodel.Any{Value: cv},
		})
	}
}

// Glob constrains the selected string field to match the glob pattern (like).
func Glob(s Selector[string], pattern string) StatementBuilderFunc {
	return func() (Statement, error) {
		return newStatement(pdm.StatementModel{
			Op:       OpLike,
			Selector: s.path,
			Pattern:  pattern,
		})
	}
}

// --- connectives ------------------------------------------------------------

// AllOf passes only if every child statement passes (and).
func AllOf(statements ...StatementBuilderFunc) StatementBuilderFunc {
	return func() (Statement, error) {
		models, err := childModels(statements)
		if err != nil {
			return Statement{}, err
		}
		return newStatement(pdm.StatementModel{Op: OpAnd, Statements: models})
	}
}

// AnyOf passes if at least one child statement passes (or).
func AnyOf(statements ...StatementBuilderFunc) StatementBuilderFunc {
	return func() (Statement, error) {
		models, err := childModels(statements)
		if err != nil {
			return Statement{}, err
		}
		return newStatement(pdm.StatementModel{Op: OpOr, Statements: models})
	}
}

// Negate passes only if the child statement fails (not).
func Negate(statement StatementBuilderFunc) StatementBuilderFunc {
	return func() (Statement, error) {
		s, err := statement()
		if err != nil {
			return Statement{}, err
		}
		return newStatement(pdm.StatementModel{Op: OpNot, Statement: &s.model})
	}
}

// --- quantifiers ------------------------------------------------------------

// Each passes only if every element of the selected list satisfies the
// statements the closure builds against the element descriptor (all).
//
//	policy.Each(ManifestFields.Shards, func(s ShardFields) []policy.StatementBuilderFunc {
//		return []policy.StatementBuilderFunc{policy.Eq(s.Codec, uint64(0x55))}
//	})
func Each[E any](s SliceSelector[E], build func(E) []StatementBuilderFunc) StatementBuilderFunc {
	return quantifier(OpAll, s.path, s.elem, build)
}

// Some passes if at least one element of the selected list satisfies the
// closure statements (any).
func Some[E any](s SliceSelector[E], build func(E) []StatementBuilderFunc) StatementBuilderFunc {
	return quantifier(OpAny, s.path, s.elem, build)
}

// EachMap is [Each] over the values of a map-valued field.
func EachMap[E any](s MapSelector[E], build func(E) []StatementBuilderFunc) StatementBuilderFunc {
	return quantifier(OpAll, s.path, s.elem, build)
}

// SomeMap is [Some] over the values of a map-valued field.
func SomeMap[E any](s MapSelector[E], build func(E) []StatementBuilderFunc) StatementBuilderFunc {
	return quantifier(OpAny, s.path, s.elem, build)
}

func quantifier[E any](op, path string, elem E, build func(E) []StatementBuilderFunc) StatementBuilderFunc {
	return func() (Statement, error) {
		inner, err := groupInner(build(elem))
		if err != nil {
			return Statement{}, fmt.Errorf("%q element: %w", op, err)
		}
		return newStatement(pdm.StatementModel{Op: op, Selector: path, Statement: inner})
	}
}

// --- helpers ----------------------------------------------------------------

func childModels(statements []StatementBuilderFunc) ([]*pdm.StatementModel, error) {
	models := make([]*pdm.StatementModel, 0, len(statements))
	for i, ctor := range statements {
		s, err := ctor()
		if err != nil {
			return nil, fmt.Errorf("child %d: %w", i, err)
		}
		models = append(models, &s.model)
	}
	return models, nil
}

// groupInner collapses an element's statements into the single inner statement
// a quantifier requires: the lone statement, or an implicit AND of several.
func groupInner(statements []StatementBuilderFunc) (*pdm.StatementModel, error) {
	switch len(statements) {
	case 0:
		return nil, fmt.Errorf("element closure returned no statements")
	case 1:
		s, err := statements[0]()
		if err != nil {
			return nil, err
		}
		return &s.model, nil
	default:
		models, err := childModels(statements)
		if err != nil {
			return nil, err
		}
		return &pdm.StatementModel{Op: OpAnd, Statements: models}, nil
	}
}
