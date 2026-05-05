package policy

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	pdm "github.com/fil-forge/ucantone/ucan/delegation/policy/datamodel"
	"github.com/fil-forge/ucantone/ucan/delegation/policy/selector"
	"github.com/gobwas/glob"
)

const (
	OpEqual              = "=="
	OpNotEqual           = "!="
	OpGreaterThan        = ">"
	OpGreaterThanOrEqual = ">="
	OpLessThan           = "<"
	OpLessThanOrEqual    = "<="
	OpAnd                = "and"
	OpOr                 = "or"
	OpNot                = "not"
	OpLike               = "like"
	OpAll                = "all"
	OpAny                = "any"
)

// UCAN Delegation uses predicate logic statements extended with jq-inspired
// selectors as a policy language. Policies are syntactically driven, and
// constrain the args field of an eventual Invocation.
//
// https://github.com/ucan-wg/delegation/blob/main/README.md#policy
type Policy struct {
	statements []Statement
}

func New(statements ...ucan.Statement) (Policy, error) {
	stmts := make([]Statement, 0, len(statements))
	for _, s := range statements {
		if ss, ok := s.(Statement); ok {
			stmts = append(stmts, ss)
		} else {
			ss, err := toStatement(s)
			if err != nil {
				return Policy{}, err
			}
			stmts = append(stmts, ss)
		}
	}
	return Policy{stmts}, nil
}

type StatementBuilderFunc func() (Statement, error)

// Build a policy from the passed policy builder functions.
func Build(statements ...StatementBuilderFunc) (Policy, error) {
	stmts := make([]Statement, 0, len(statements))
	for _, ctor := range statements {
		s, err := ctor()
		if err != nil {
			return Policy{}, err
		}
		stmts = append(stmts, s)
	}
	return Policy{stmts}, nil
}

// A Policy is always given as an array of predicates. This top-level array is
// implicitly treated as a logical "and", where args MUST pass validation of
// every top-level predicate.
func (p Policy) Statements() []ucan.Statement {
	stmts := make([]ucan.Statement, 0, len(p.statements))
	for _, s := range p.statements {
		stmts = append(stmts, s)
	}
	return stmts
}

func (p Policy) MarshalCBOR(w io.Writer) error {
	statements := make([]pdm.StatementModel, 0, len(p.statements))
	for _, s := range p.statements {
		statements = append(statements, s.model)
	}
	model := pdm.PolicyModel{Statements: statements}
	return model.MarshalCBOR(w)
}

func (p *Policy) UnmarshalCBOR(r io.Reader) error {
	*p = Policy{}
	var policyModel pdm.PolicyModel
	err := policyModel.UnmarshalCBOR(r)
	if err != nil {
		return err
	}
	for i, m := range policyModel.Statements {
		s, err := newStatement(m)
		if err != nil {
			return fmt.Errorf(`unmarshaling policy statement %d with operator "%s": %w`, i, m.Op, err)
		}
		p.statements = append(p.statements, s)
	}
	return nil
}

func (p Policy) MarshalDagJSON(w io.Writer) error {
	statements := make([]pdm.StatementModel, 0, len(p.statements))
	for _, s := range p.statements {
		statements = append(statements, s.model)
	}
	model := pdm.PolicyModel{Statements: statements}
	return model.MarshalDagJSON(w)
}

func (p *Policy) UnmarshalDagJSON(r io.Reader) error {
	*p = Policy{}
	var policyModel pdm.PolicyModel
	err := policyModel.UnmarshalDagJSON(r)
	if err != nil {
		return err
	}
	for i, m := range policyModel.Statements {
		s, err := newStatement(m)
		if err != nil {
			return fmt.Errorf(`unmarshaling policy statement %d with operator "%s": %w`, i, m.Op, err)
		}
		p.statements = append(p.statements, s)
	}
	return nil
}

func (p Policy) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	err := p.MarshalDagJSON(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *Policy) UnmarshalJSON(b []byte) error {
	return p.UnmarshalDagJSON(bytes.NewReader(b))
}

func (p Policy) String() string {
	data, err := p.MarshalJSON()
	if err != nil {
		return fmt.Sprintf("Error: marshaling policy to string: %s", err.Error())
	}
	return string(data)
}

type Statement struct {
	model      pdm.StatementModel
	statement  *Statement
	statements []*Statement
	selector   selector.Selector
	glob       glob.Glob
}

func newStatement(m pdm.StatementModel) (Statement, error) {
	s := Statement{model: m}
	switch m.Op {
	case OpEqual, OpNotEqual, OpGreaterThan, OpGreaterThanOrEqual, OpLessThan, OpLessThanOrEqual, OpAll, OpAny, OpLike:
		sel, err := selector.Parse(m.Selector)
		if err != nil {
			return Statement{}, fmt.Errorf(`parsing selector for "%s" operation: %w`, m.Op, err)
		}
		s.selector = sel
	}
	if m.Op == OpLike {
		g, err := glob.Compile(m.Pattern)
		if err != nil {
			return Statement{}, fmt.Errorf(`compiling glob for "%s" operation: %w`, m.Op, err)
		}
		s.glob = g
	}
	switch m.Op {
	case OpNot, OpAny, OpAll:
		stmt, err := newStatement(*m.Statement)
		if err != nil {
			return Statement{}, fmt.Errorf(`creating statement for "%s" operation: %w`, m.Op, err)
		}
		s.statement = &stmt
	case OpAnd, OpOr:
		stmts := make([]*Statement, 0, len(m.Statements))
		for i, m := range m.Statements {
			ss, err := newStatement(*m)
			if err != nil {
				return Statement{}, fmt.Errorf(`creating statement %d of "%s" operation: %w`, i, m.Op, err)
			}
			stmts = append(stmts, &ss)
		}
		s.statements = stmts
	}
	return s, nil
}

func (s Statement) Operator() string {
	return s.model.Op
}

func (s Statement) Selector() string {
	return s.model.Selector
}

func (s Statement) Argument() any {
	switch s.model.Op {
	case OpEqual, OpNotEqual, OpGreaterThan, OpGreaterThanOrEqual, OpLessThan, OpLessThanOrEqual:
		return s.model.Value.Value
	case OpAnd, OpOr, OpAll, OpAny:
		return s.statements
	case OpNot:
		return s.statement
	case OpLike:
		return s.model.Pattern
	default:
		return fmt.Errorf("unknown statement: %s", s.model.Op)
	}
}

func (s Statement) MarshalCBOR(w io.Writer) error {
	return s.model.MarshalCBOR(w)
}

func (s *Statement) UnmarshalCBOR(r io.Reader) error {
	model := pdm.StatementModel{}
	if err := model.UnmarshalCBOR(r); err != nil {
		return err
	}
	stmt, err := newStatement(model)
	if err != nil {
		return err
	}
	*s = stmt
	return nil
}

func (s Statement) MarshalDagJSON(w io.Writer) error {
	return s.model.MarshalDagJSON(w)
}

func (s *Statement) UnmarshalDagJSON(r io.Reader) error {
	model := pdm.StatementModel{}
	if err := model.UnmarshalDagJSON(r); err != nil {
		return err
	}
	stmt, err := newStatement(model)
	if err != nil {
		return err
	}
	*s = stmt
	return nil
}

func Equal(sel string, value any) StatementBuilderFunc {
	return func() (Statement, error) {
		return newStatement(pdm.StatementModel{
			Op:       OpEqual,
			Selector: sel,
			Value:    &datamodel.Any{Value: value},
		})
	}
}

func NotEqual(sel string, value any) StatementBuilderFunc {
	return func() (Statement, error) {
		return newStatement(pdm.StatementModel{
			Op:       OpNotEqual,
			Selector: sel,
			Value:    &datamodel.Any{Value: value},
		})
	}
}

func GreaterThan(sel string, value any) StatementBuilderFunc {
	return func() (Statement, error) {
		return newStatement(pdm.StatementModel{
			Op:       OpGreaterThan,
			Selector: sel,
			Value:    &datamodel.Any{Value: value},
		})
	}
}

func GreaterThanOrEqual(sel string, value any) StatementBuilderFunc {
	return func() (Statement, error) {
		return newStatement(pdm.StatementModel{
			Op:       OpGreaterThanOrEqual,
			Selector: sel,
			Value:    &datamodel.Any{Value: value},
		})
	}
}

func LessThan(sel string, value any) StatementBuilderFunc {
	return func() (Statement, error) {
		return newStatement(pdm.StatementModel{
			Op:       OpLessThan,
			Selector: sel,
			Value:    &datamodel.Any{Value: value},
		})
	}
}

func LessThanOrEqual(sel string, value any) StatementBuilderFunc {
	return func() (Statement, error) {
		return newStatement(pdm.StatementModel{
			Op:       OpLessThanOrEqual,
			Selector: sel,
			Value:    &datamodel.Any{Value: value},
		})
	}
}

func Not(stmt StatementBuilderFunc) StatementBuilderFunc {
	return func() (Statement, error) {
		s, err := stmt()
		if err != nil {
			return Statement{}, err
		}
		return newStatement(pdm.StatementModel{
			Op:        OpNot,
			Statement: &s.model,
		})
	}
}

func And(stmts ...StatementBuilderFunc) StatementBuilderFunc {
	return func() (Statement, error) {
		models := make([]*pdm.StatementModel, 0, len(stmts))
		for _, ctor := range stmts {
			s, err := ctor()
			if err != nil {
				return Statement{}, err
			}
			models = append(models, &s.model)
		}
		return newStatement(pdm.StatementModel{
			Op:         OpAnd,
			Statements: models,
		})
	}
}

func Or(stmts ...StatementBuilderFunc) StatementBuilderFunc {
	return func() (Statement, error) {
		models := make([]*pdm.StatementModel, 0, len(stmts))
		for _, ctor := range stmts {
			s, err := ctor()
			if err != nil {
				return Statement{}, err
			}
			models = append(models, &s.model)
		}
		return newStatement(pdm.StatementModel{
			Op:         OpOr,
			Statements: models,
		})
	}
}

func Like(sel string, pattern string) StatementBuilderFunc {
	return func() (Statement, error) {
		return newStatement(pdm.StatementModel{
			Op:       OpLike,
			Selector: sel,
			Pattern:  pattern,
		})
	}
}

func All(sel string, stmt StatementBuilderFunc) StatementBuilderFunc {
	return func() (Statement, error) {
		s, err := stmt()
		if err != nil {
			return Statement{}, err
		}
		return newStatement(pdm.StatementModel{
			Op:        OpAll,
			Selector:  sel,
			Statement: &s.model,
		})
	}
}

func Any(sel string, stmt StatementBuilderFunc) StatementBuilderFunc {
	return func() (Statement, error) {
		s, err := stmt()
		if err != nil {
			return Statement{}, err
		}
		return newStatement(pdm.StatementModel{
			Op:        OpAny,
			Selector:  sel,
			Statement: &s.model,
		})
	}
}

// toStatement converts a [ucan.Statement] to a [Statement]
func toStatement(stmt ucan.Statement) (Statement, error) {
	if s, ok := stmt.(Statement); ok {
		return s, nil
	}
	model := pdm.StatementModel{
		Op:       stmt.Operator(),
		Selector: stmt.Selector(),
	}
	switch stmt.Operator() {
	case OpEqual, OpNotEqual, OpGreaterThan, OpGreaterThanOrEqual, OpLessThan, OpLessThanOrEqual:
		model.Value = &datamodel.Any{Value: stmt.Argument()}
	case OpAnd, OpOr:
		rt := reflect.TypeOf(stmt.Argument())
		switch rt.Kind() {
		case reflect.Slice:
			val := reflect.ValueOf(stmt.Argument())
			models := make([]*pdm.StatementModel, 0, val.Len())
			for i := range val.Len() {
				ns, ok := val.Index(i).Interface().(ucan.Statement)
				if !ok {
					return Statement{}, fmt.Errorf(`"%s" statement argument %d is not a statement`, stmt.Operator(), i)
				}
				s, err := toStatement(ns)
				if err != nil {
					return Statement{}, fmt.Errorf(`encoding "%s" statement argument: %w`, stmt.Operator(), err)
				}
				models = append(models, &s.model)
			}
			model.Statements = models
		default:
			return Statement{}, fmt.Errorf(`unexpected argument type for operator "%s": %s`, stmt.Operator(), rt.Kind())
		}
	case OpAll, OpAny, OpNot:
		ns, ok := stmt.Argument().(ucan.Statement)
		if !ok {
			return Statement{}, fmt.Errorf(`"%s" statement argument is not a statement`, stmt.Operator())
		}
		s, err := toStatement(ns)
		if err != nil {
			return Statement{}, fmt.Errorf(`encoding "%s" statement argument: %w`, stmt.Operator(), err)
		}
		model.Statement = &s.model
	case OpLike:
		pattern, ok := stmt.Argument().(string)
		if !ok {
			return Statement{}, fmt.Errorf(`"%s" statement argument is not a string`, stmt.Operator())
		}
		model.Pattern = pattern
	default:
		return Statement{}, fmt.Errorf("unknown statement: %s", stmt.Operator())
	}
	return newStatement(model)
}

// Parse a policy encoded as a DAG-jSON string.
func Parse(input string) (Policy, error) {
	pol := Policy{}
	err := pol.UnmarshalDagJSON(strings.NewReader(input))
	if err != nil {
		return Policy{}, err
	}
	return pol, nil
}
