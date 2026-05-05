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
func Match(policy ucan.Policy, value any) (bool, error) {
	for _, stmt := range policy.Statements() {
		ok, err := MatchStatement(stmt, value)
		if !ok {
			return ok, err
		}
	}
	return true, nil
}

func MatchStatement(statement ucan.Statement, value any) (bool, error) {
	s, err := toStatement(statement)
	if err != nil {
		return false, err
	}
	switch statement.Operator() {
	case OpEqual:
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return false, err
		}
		var statementValue any
		if s.model.Value != nil {
			statementValue = s.model.Value.Value
		}
		if !reflect.DeepEqual(statementValue, selectedValue) {
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" does not equal "%v"`, s.Selector(), selectedValue, statementValue))
		}
		return true, nil
	case OpNotEqual:
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return false, err
		}
		var statementValue any
		if s.model.Value != nil {
			statementValue = s.model.Value.Value
		}
		if reflect.DeepEqual(statementValue, selectedValue) {
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" equals "%v"`, s.Selector(), selectedValue, statementValue))
		}
		return true, nil
	case OpGreaterThan:
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return false, err
		}
		if selectedValue == nil {
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not applicable to operator "%s"`, s.Selector(), selectedValue, OpGreaterThan))
		}
		var statementValue any
		if s.model.Value != nil {
			statementValue = s.model.Value.Value
		}
		if !isOrdered(selectedValue, statementValue, gt) {
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not greater than "%v"`, s.Selector(), selectedValue, statementValue))
		}
		return true, nil
	case OpGreaterThanOrEqual:
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return false, err
		}
		if selectedValue == nil {
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not applicable to operator "%s"`, s.Selector(), selectedValue, OpGreaterThanOrEqual))
		}
		var statementValue any
		if s.model.Value != nil {
			statementValue = s.model.Value.Value
		}
		if !isOrdered(selectedValue, statementValue, gte) {
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not greater than or equal to "%v"`, s.Selector(), selectedValue, statementValue))
		}
		return true, nil
	case OpLessThan:
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return false, err
		}
		if selectedValue == nil {
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not applicable to operator "%s"`, s.Selector(), selectedValue, OpLessThan))
		}
		var statementValue any
		if s.model.Value != nil {
			statementValue = s.model.Value.Value
		}
		if !isOrdered(selectedValue, statementValue, lt) {
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not less than "%v"`, s.Selector(), selectedValue, statementValue))
		}
		return true, nil
	case OpLessThanOrEqual:
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return false, err
		}
		if selectedValue == nil {
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not applicable to operator "%s"`, s.Selector(), selectedValue, OpLessThanOrEqual))
		}
		var statementValue any
		if s.model.Value != nil {
			statementValue = s.model.Value.Value
		}
		if !isOrdered(selectedValue, statementValue, lte) {
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not less than or equal to "%v"`, s.Selector(), selectedValue, statementValue))
		}
		return true, nil
	case OpNot:
		ss, ok := statement.Argument().(ucan.Statement)
		if !ok {
			return false, fmt.Errorf(`"%s" operator argument is not a statement`, s.Operator())
		}
		ok, _ = MatchStatement(ss, value)
		if ok {
			return false, NewMatchError(statement, errors.New("not true is false"))
		}
		return true, nil
	case OpAnd:
		for _, s := range s.statements {
			ok, err := MatchStatement(s, value)
			if !ok {
				return false, err
			}
		}
		return true, nil
	case OpOr:
		if len(s.statements) == 0 {
			return true, nil
		}
		for _, s := range s.statements {
			ok, _ := MatchStatement(s, value)
			if ok {
				return true, nil
			}
		}
		return false, fmt.Errorf(`"%v" did not match any statements`, value)
	case OpLike:
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return false, err
		}
		v, ok := selectedValue.(string)
		if !ok {
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not applicable to operator "%s"`, s.Selector(), selectedValue, OpLike))
		}
		if !s.glob.Match(v) {
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not like "%v"`, s.Selector(), selectedValue, s.model.Pattern))
		}
		return true, nil
	case OpAll:
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return false, err
		}
		selectedValueVal := reflect.ValueOf(selectedValue)
		switch selectedValueVal.Kind() {
		case reflect.Slice:
			pol := Policy{[]Statement{*s.statement}}
			for i := range selectedValueVal.Len() {
				itemVal := selectedValueVal.Index(i).Interface()
				ok, err := Match(pol, itemVal)
				if !ok {
					return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" did not match all statements: %w`, s.Selector(), itemVal, err))
				}
			}
			return true, nil
		case reflect.Map:
			pol := Policy{[]Statement{*s.statement}}
			iter := selectedValueVal.MapRange()
			for iter.Next() {
				entVal := iter.Value().Interface()
				ok, err := Match(pol, entVal)
				if !ok {
					return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" did not match all statements: %w`, s.Selector(), entVal, err))
				}
			}
		default:
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not a list or map`, s.Selector(), selectedValue))
		}
		return true, nil
	case OpAny:
		selectedValue, err := selector.Select(s.selector, value)
		if err != nil {
			return false, err
		}
		selectedValueVal := reflect.ValueOf(selectedValue)
		switch selectedValueVal.Kind() {
		case reflect.Slice:
			pol := Policy{[]Statement{*s.statement}}
			for i := range selectedValueVal.Len() {
				ok, _ := Match(pol, selectedValueVal.Index(i).Interface())
				if ok {
					return true, nil
				}
			}
		case reflect.Map:
			pol := Policy{[]Statement{*s.statement}}
			iter := selectedValueVal.MapRange()
			for iter.Next() {
				ok, _ := Match(pol, iter.Value().Interface())
				if ok {
					return true, nil
				}
			}
		default:
			return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" is not a list or map`, s.Selector(), selectedValue))
		}
		return false, NewMatchError(statement, fmt.Errorf(`matching "%s": "%v" did not match any statements`, s.Selector(), selectedValue))
	}
	panic(fmt.Errorf("unknown statement operator: %s", statement.Operator()))
}

func isOrdered(a any, b any, satisfies func(order int) bool) bool {
	if aint, ok := a.(int); ok {
		a = int64(aint)
	}
	if bint, ok := b.(int); ok {
		b = int64(bint)
	}
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
