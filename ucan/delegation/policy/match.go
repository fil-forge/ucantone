package policy

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation/policy/selector"
)

// Match determines if the value matches the policy document. If the value fails
// to match, the returned error will contain details of the failure.
func Match(policy ucan.Policy, value any) error {
	for _, stmt := range policy.Statements() {
		err := MatchStatement(stmt, value)
		if err != nil {
			return err
		}
	}
	return nil
}

// normalize converts values to their canonical IPLD form for comparison, so
// that a statement literal (which may be a named Go type like
// multihash.Multihash) compares equal to the plain []byte/int64/etc. the
// selector decodes out of invocation arguments. See [canonicalize].
func normalize(value any) any {
	return normalizeValue(value)
}

func MatchStatement(statement ucan.Statement, value any) error {
	s, err := toStatement(statement)
	if err != nil {
		return err
	}

	switch statement.Operator() {
	case OpEqual, OpNotEqual, OpGreaterThan, OpGreaterThanOrEqual, OpLessThan, OpLessThanOrEqual:
		// https://github.com/ucan-wg/delegation#comparisons
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return err
		}
		selectedValue = normalize(selectedValue)

		var statementValue any
		if s.model.Value != nil {
			statementValue = s.model.Value.Value
			statementValue = normalize(statementValue)
		}

		switch statement.Operator() {
		case OpEqual:
			if !valuesEqual(statementValue, selectedValue) {
				return NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" does not equal "%v"`, s.Selector(), selectedValue, statementValue))
			}
			return nil
		case OpNotEqual:
			if valuesEqual(statementValue, selectedValue) {
				return NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" equals "%v"`, s.Selector(), selectedValue, statementValue))
			}
			return nil

		case OpGreaterThan, OpGreaterThanOrEqual, OpLessThan, OpLessThanOrEqual:
			var comp func(order int) bool
			switch statement.Operator() {
			case OpGreaterThan:
				comp = gt
			case OpGreaterThanOrEqual:
				comp = gte
			case OpLessThan:
				comp = lt
			case OpLessThanOrEqual:
				comp = lte
			}

			if selectedValue == nil {
				return NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not applicable to operator "%s"`, s.Selector(), selectedValue, statement.Operator()))
			}

			if !isOrdered(selectedValue, statementValue, comp) {
				return NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not %s than "%v"`, s.Selector(), selectedValue, statement.Operator(), statementValue))
			}
			return nil
		}

	case OpNot:
		// https://github.com/ucan-wg/delegation#not
		ss, ok := statement.Argument().(ucan.Statement)
		if !ok {
			return fmt.Errorf(`"%s" operator argument is not a statement`, s.Operator())
		}
		err = MatchStatement(ss, value)
		if err == nil {
			return NewMatchError(statement, errors.New("not true is false"))
		}
		return nil
	case OpAnd:
		// https://github.com/ucan-wg/delegation#and
		for _, s := range s.statements {
			err := MatchStatement(s, value)
			if err != nil {
				return err
			}
		}
		return nil
	case OpOr:
		// https://github.com/ucan-wg/delegation#or
		if len(s.statements) == 0 {
			return nil
		}
		for _, s := range s.statements {
			err := MatchStatement(s, value)
			if err == nil {
				return nil
			}
		}
		return fmt.Errorf(`"%v" did not match any statements`, value)
	case OpLike:
		// https://github.com/ucan-wg/delegation#like
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return err
		}
		v, ok := selectedValue.(string)
		if !ok {
			return NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not applicable to operator "%s"`, s.Selector(), selectedValue, OpLike))
		}
		if !s.glob.Match(v) {
			return NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not like "%v"`, s.Selector(), selectedValue, s.model.Pattern))
		}
		return nil
	case OpAll:
		// https://github.com/ucan-wg/delegation#all
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return err
		}
		selectedValueVal := reflect.ValueOf(selectedValue)
		switch selectedValueVal.Kind() {
		case reflect.Slice:
			pol := Policy{[]Statement{*s.statement}}
			for i := range selectedValueVal.Len() {
				itemVal := selectedValueVal.Index(i).Interface()
				err := Match(pol, itemVal)
				if err != nil {
					return NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" did not match all statements: %w`, s.Selector(), itemVal, err))
				}
			}
			return nil
		case reflect.Map:
			pol := Policy{[]Statement{*s.statement}}
			iter := selectedValueVal.MapRange()
			for iter.Next() {
				entVal := iter.Value().Interface()
				err := Match(pol, entVal)
				if err != nil {
					return NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" did not match all statements: %w`, s.Selector(), entVal, err))
				}
			}
		default:
			return NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not a list or map`, s.Selector(), selectedValue))
		}
		return nil
	case OpAny:
		// https://github.com/ucan-wg/delegation#any
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return err
		}
		selectedValueVal := reflect.ValueOf(selectedValue)
		switch selectedValueVal.Kind() {
		case reflect.Slice:
			pol := Policy{[]Statement{*s.statement}}
			for i := range selectedValueVal.Len() {
				err := Match(pol, selectedValueVal.Index(i).Interface())
				if err == nil {
					return nil
				}
			}
		case reflect.Map:
			pol := Policy{[]Statement{*s.statement}}
			iter := selectedValueVal.MapRange()
			for iter.Next() {
				err := Match(pol, iter.Value().Interface())
				if err == nil {
					return nil
				}
			}
		default:
			return NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not a list or map`, s.Selector(), selectedValue))
		}
		return NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" did not match any statements`, s.Selector(), selectedValue))
	}
	panic(fmt.Errorf("unknown statement operator: %s", statement.Operator()))
}

func isOrdered(a any, b any, satisfies func(order int) bool) bool {
	// Integers — int64 and CBOR bignums (*big.Int) — share one ordering: both
	// sides are promoted to *big.Int and compared by value, so an int64 and a
	// numerically-equal bignum order consistently. See [canonicalize].
	if ab, ok := asBigInt(a); ok {
		if bb, ok := asBigInt(b); ok {
			return satisfies(ab.Cmp(bb))
		}
	}
	// Strings order lexicographically. Both sides come through canonicalize as
	// plain strings (named string types are flattened), so a string field and
	// a string literal compare directly.
	if as, ok := a.(string); ok {
		if bs, ok := b.(string); ok {
			return satisfies(strings.Compare(as, bs))
		}
	}
	// Floats are intentionally unsupported: neither the CBOR nor the DAG-JSON
	// codec represents them, so a float literal could not round-trip. The
	// typed builders exclude float field types via the policy.Ordered
	// constraint, so this is unreachable from generated descriptors.
	return false
}

// asBigInt promotes the integer kinds canonicalize can produce (int64, or a
// *big.Int for magnitudes that overflow int64) to a *big.Int for comparison.
func asBigInt(v any) (*big.Int, bool) {
	switch x := v.(type) {
	case *big.Int:
		return x, x != nil
	case int64:
		return big.NewInt(x), true
	}
	return nil, false
}

// valuesEqual reports IPLD value equality for the == / != operators. It differs
// from reflect.DeepEqual in two ways: integers compare by numeric value across
// the int64/bignum split (so DeepEqual's type-identity sensitivity does not
// make a bignum silently never match), and lists/maps recurse through the same
// rule. All other kinds fall back to DeepEqual.
func valuesEqual(a, b any) bool {
	if ai, ok := asBigInt(a); ok {
		bi, ok := asBigInt(b)
		return ok && ai.Cmp(bi) == 0
	}
	switch av := a.(type) {
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !valuesEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, x := range av {
			y, ok := bv[k]
			if !ok || !valuesEqual(x, y) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

func gt(order int) bool  { return order == 1 }
func gte(order int) bool { return order == 0 || order == 1 }
func lt(order int) bool  { return order == -1 }
func lte(order int) bool { return order == 0 || order == -1 }
