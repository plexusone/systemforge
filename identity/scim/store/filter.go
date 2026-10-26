package store

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/filter"
)

// Filter translation fails closed: an attribute, operator, value type or
// expression the store cannot evaluate is an invalidFilter error (RFC 7644
// section 3.4.2.2), never a constraint that is silently dropped, so a
// filter never matches more resources than it names.

// unsupportedFilter returns the invalidFilter error for a construct the
// store cannot evaluate.
func unsupportedFilter(format string, args ...any) error {
	return scim.ErrInvalidFilter(fmt.Sprintf(format, args...))
}

// stringValue returns a comparison's value as a string. pr has no value.
func stringValue(node *filter.ComparisonNode) (string, error) {
	if node.Operator == filter.OpPresent {
		return "", nil
	}
	v, ok := node.Value.(string)
	if !ok {
		return "", unsupportedFilter("%s takes a string value", node.AttributePath)
	}
	return v, nil
}

// timeValue returns a comparison's value as an RFC 3339 time.
func timeValue(node *filter.ComparisonNode) (time.Time, error) {
	v, ok := node.Value.(string)
	if !ok {
		return time.Time{}, unsupportedFilter("%s takes an RFC 3339 timestamp", node.AttributePath)
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, unsupportedFilter("%s takes an RFC 3339 timestamp", node.AttributePath)
	}
	return t, nil
}

func badOperator(node *filter.ComparisonNode) error {
	return unsupportedFilter("operator %s is not supported for %s", node.Operator, node.AttributePath)
}

// buildUserPredicates builds Ent predicates from a SCIM filter.
func (s *EntStore) buildUserPredicates(filterExpr string) ([]predicate.Principal, error) {
	node, err := filter.ParseFilter(filterExpr)
	if err != nil {
		return nil, scim.ErrInvalidFilter(err.Error())
	}
	if node == nil {
		return nil, nil
	}
	p, err := s.userPredicate(node)
	if err != nil {
		return nil, err
	}
	return []predicate.Principal{p}, nil
}

// userPredicate translates a filter node to one principal predicate.
//
//nolint:dupl // Mirrors groupPredicate - same traversal logic for different predicate types
func (s *EntStore) userPredicate(node filter.Node) (predicate.Principal, error) {
	switch n := node.(type) {
	case *filter.ComparisonNode:
		return s.userComparisonToPredicate(n)
	case *filter.LogicalAndNode:
		left, err := s.userPredicate(n.Left)
		if err != nil {
			return nil, err
		}
		right, err := s.userPredicate(n.Right)
		if err != nil {
			return nil, err
		}
		return principal.And(left, right), nil
	case *filter.LogicalOrNode:
		left, err := s.userPredicate(n.Left)
		if err != nil {
			return nil, err
		}
		right, err := s.userPredicate(n.Right)
		if err != nil {
			return nil, err
		}
		return principal.Or(left, right), nil
	case *filter.LogicalNotNode:
		inner, err := s.userPredicate(n.Operand)
		if err != nil {
			return nil, err
		}
		return principal.Not(inner), nil
	default:
		return nil, unsupportedFilter("unsupported filter expression %s", node.String())
	}
}

// hasEmail wraps a Human email predicate as a Principal predicate.
func hasEmail(p predicate.Human) predicate.Principal {
	return principal.HasHumanWith(p)
}

// userComparisonToPredicate converts a comparison node to a principal
// predicate. userName and emails.value are not case-exact (RFC 7643), so
// equality and containment ignore case.
func (s *EntStore) userComparisonToPredicate(node *filter.ComparisonNode) (predicate.Principal, error) {
	attr := strings.ToLower(node.AttributePath)

	switch attr {
	case "id":
		value, err := stringValue(node)
		if err != nil {
			return nil, err
		}
		id, perr := uuid.Parse(value)
		switch node.Operator {
		case filter.OpEqual:
			if perr != nil {
				return principal.IDIn(), nil // no principal has a malformed ID
			}
			return principal.IDEQ(id), nil
		case filter.OpNotEqual:
			if perr != nil {
				return principal.Not(principal.IDIn()), nil
			}
			return principal.IDNEQ(id), nil
		}
	case "externalid":
		// SystemForge stores no externalId for users, so no user has one.
		switch node.Operator {
		case filter.OpEqual, filter.OpPresent:
			return principal.IDIn(), nil
		}
	case "username", "emails.value":
		value, err := stringValue(node)
		if err != nil {
			return nil, err
		}
		switch node.Operator {
		case filter.OpEqual:
			return hasEmail(human.EmailEqualFold(value)), nil
		case filter.OpNotEqual:
			return principal.Not(hasEmail(human.EmailEqualFold(value))), nil
		case filter.OpContains:
			return hasEmail(human.EmailContainsFold(value)), nil
		case filter.OpStartsWith:
			return hasEmail(human.EmailHasPrefix(value)), nil
		case filter.OpEndsWith:
			return hasEmail(human.EmailHasSuffix(value)), nil
		case filter.OpPresent:
			return hasEmail(human.EmailNEQ("")), nil
		}
	case "displayname", "name.formatted":
		value, err := stringValue(node)
		if err != nil {
			return nil, err
		}
		switch node.Operator {
		case filter.OpEqual:
			return principal.DisplayNameEQ(value), nil
		case filter.OpNotEqual:
			return principal.DisplayNameNEQ(value), nil
		case filter.OpContains:
			return principal.DisplayNameContains(value), nil
		case filter.OpStartsWith:
			return principal.DisplayNameHasPrefix(value), nil
		case filter.OpEndsWith:
			return principal.DisplayNameHasSuffix(value), nil
		case filter.OpPresent:
			return principal.DisplayNameNEQ(""), nil
		}
	case "active":
		boolValue, ok := node.Value.(bool)
		if !ok {
			return nil, unsupportedFilter("active takes a boolean value")
		}
		switch node.Operator {
		case filter.OpEqual:
			return principal.ActiveEQ(boolValue), nil
		case filter.OpNotEqual:
			return principal.ActiveNEQ(boolValue), nil
		}
	case "meta.created", "meta.lastmodified":
		t, err := timeValue(node)
		if err != nil {
			return nil, err
		}
		created := attr == "meta.created"
		switch node.Operator {
		case filter.OpGreaterThan:
			return pick(created, principal.CreatedAtGT, principal.UpdatedAtGT)(t), nil
		case filter.OpGreaterThanOrEqual:
			return pick(created, principal.CreatedAtGTE, principal.UpdatedAtGTE)(t), nil
		case filter.OpLessThan:
			return pick(created, principal.CreatedAtLT, principal.UpdatedAtLT)(t), nil
		case filter.OpLessThanOrEqual:
			return pick(created, principal.CreatedAtLTE, principal.UpdatedAtLTE)(t), nil
		}
	default:
		return nil, unsupportedFilter("filtering on %s is not supported", node.AttributePath)
	}
	return nil, badOperator(node)
}

// pick returns a when first is true, b otherwise.
func pick[T any](first bool, a, b T) T {
	if first {
		return a
	}
	return b
}

// buildGroupPredicates builds Ent predicates from a SCIM filter.
func (s *EntStore) buildGroupPredicates(filterExpr string) ([]predicate.Organization, error) {
	node, err := filter.ParseFilter(filterExpr)
	if err != nil {
		return nil, scim.ErrInvalidFilter(err.Error())
	}
	if node == nil {
		return nil, nil
	}
	p, err := s.groupPredicate(node)
	if err != nil {
		return nil, err
	}
	return []predicate.Organization{p}, nil
}

// groupPredicate translates a filter node to one organization predicate.
//
//nolint:dupl // Mirrors userPredicate - same traversal logic for different predicate types
func (s *EntStore) groupPredicate(node filter.Node) (predicate.Organization, error) {
	switch n := node.(type) {
	case *filter.ComparisonNode:
		return s.groupComparisonToPredicate(n)
	case *filter.LogicalAndNode:
		left, err := s.groupPredicate(n.Left)
		if err != nil {
			return nil, err
		}
		right, err := s.groupPredicate(n.Right)
		if err != nil {
			return nil, err
		}
		return organization.And(left, right), nil
	case *filter.LogicalOrNode:
		left, err := s.groupPredicate(n.Left)
		if err != nil {
			return nil, err
		}
		right, err := s.groupPredicate(n.Right)
		if err != nil {
			return nil, err
		}
		return organization.Or(left, right), nil
	case *filter.LogicalNotNode:
		inner, err := s.groupPredicate(n.Operand)
		if err != nil {
			return nil, err
		}
		return organization.Not(inner), nil
	default:
		return nil, unsupportedFilter("unsupported filter expression %s", node.String())
	}
}

// groupComparisonToPredicate converts a comparison node to an organization predicate.
func (s *EntStore) groupComparisonToPredicate(node *filter.ComparisonNode) (predicate.Organization, error) {
	attr := strings.ToLower(node.AttributePath)

	switch attr {
	case "id":
		value, err := stringValue(node)
		if err != nil {
			return nil, err
		}
		id, perr := uuid.Parse(value)
		switch node.Operator {
		case filter.OpEqual:
			if perr != nil {
				return organization.IDIn(), nil
			}
			return organization.IDEQ(id), nil
		case filter.OpNotEqual:
			if perr != nil {
				return organization.Not(organization.IDIn()), nil
			}
			return organization.IDNEQ(id), nil
		}
	case "displayname":
		value, err := stringValue(node)
		if err != nil {
			return nil, err
		}
		switch node.Operator {
		case filter.OpEqual:
			return organization.NameEQ(value), nil
		case filter.OpNotEqual:
			return organization.NameNEQ(value), nil
		case filter.OpContains:
			return organization.NameContains(value), nil
		case filter.OpStartsWith:
			return organization.NameHasPrefix(value), nil
		case filter.OpEndsWith:
			return organization.NameHasSuffix(value), nil
		case filter.OpPresent:
			return organization.NameNEQ(""), nil
		}
	case "externalid":
		value, err := stringValue(node)
		if err != nil {
			return nil, err
		}
		switch node.Operator {
		case filter.OpEqual:
			return organization.SlugEQ(value), nil
		case filter.OpNotEqual:
			return organization.SlugNEQ(value), nil
		case filter.OpPresent:
			return organization.SlugNEQ(""), nil
		}
	case "meta.created", "meta.lastmodified":
		t, err := timeValue(node)
		if err != nil {
			return nil, err
		}
		created := attr == "meta.created"
		switch node.Operator {
		case filter.OpGreaterThan:
			return pick(created, organization.CreatedAtGT, organization.UpdatedAtGT)(t), nil
		case filter.OpGreaterThanOrEqual:
			return pick(created, organization.CreatedAtGTE, organization.UpdatedAtGTE)(t), nil
		case filter.OpLessThan:
			return pick(created, organization.CreatedAtLT, organization.UpdatedAtLT)(t), nil
		case filter.OpLessThanOrEqual:
			return pick(created, organization.CreatedAtLTE, organization.UpdatedAtLTE)(t), nil
		}
	default:
		return nil, unsupportedFilter("filtering on %s is not supported", node.AttributePath)
	}
	return nil, badOperator(node)
}
