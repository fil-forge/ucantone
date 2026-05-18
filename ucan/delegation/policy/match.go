package policy

import (
	"cmp"
	"errors"
	"fmt"
	"reflect"

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

// normalize converts values to their normalized forms for comparison.
// Currently, it converts int to int64. It may do more in the future to cover
// other types.
func normalize(value any) any {
	if intVal, ok := value.(int); ok {
		return int64(intVal)
	}
	return value
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
			if !reflect.DeepEqual(statementValue, selectedValue) {
				return NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" does not equal "%v"`, s.Selector(), selectedValue, statementValue))
			}
			return nil
		case OpNotEqual:
			if reflect.DeepEqual(statementValue, selectedValue) {
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
	if aint64, ok := a.(int64); ok {
		if bint64, ok := b.(int64); ok {
			return satisfies(cmp.Compare(aint64, bint64))
		}
	}
	// TODO: support float
	return false
}

func gt(order int) bool  { return order == 1 }
func gte(order int) bool { return order == 0 || order == 1 }
func lt(order int) bool  { return order == -1 }
func lte(order int) bool { return order == 0 || order == -1 }
