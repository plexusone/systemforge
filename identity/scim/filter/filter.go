// Package filter provides SCIM filter expression parsing and evaluation.
package filter

import (
	"fmt"
	"strings"
)

// Operator represents a SCIM filter operator.
type Operator string

// Filter operators as defined in RFC 7644 Section 3.4.2.2.
const (
	OpEqual              Operator = "eq"
	OpNotEqual           Operator = "ne"
	OpContains           Operator = "co"
	OpStartsWith         Operator = "sw"
	OpEndsWith           Operator = "ew"
	OpPresent            Operator = "pr"
	OpGreaterThan        Operator = "gt"
	OpGreaterThanOrEqual Operator = "ge"
	OpLessThan           Operator = "lt"
	OpLessThanOrEqual    Operator = "le"
)

// Logical operators.
const (
	OpAnd Operator = "and"
	OpOr  Operator = "or"
	OpNot Operator = "not"
)

// NodeType represents the type of a filter AST node.
type NodeType int

const (
	NodeComparison NodeType = iota
	NodeLogicalAnd
	NodeLogicalOr
	NodeLogicalNot
	NodeValuePath
)

// Node represents a node in the filter AST.
type Node interface {
	Type() NodeType
	String() string
}

// ComparisonNode represents a comparison expression (e.g., "userName eq 'john'").
type ComparisonNode struct {
	AttributePath string
	Operator      Operator
	Value         any
}

// Type returns the node type.
func (n *ComparisonNode) Type() NodeType {
	return NodeComparison
}

// String returns the string representation of the node.
func (n *ComparisonNode) String() string {
	if n.Operator == OpPresent {
		return fmt.Sprintf("%s pr", n.AttributePath)
	}
	return fmt.Sprintf("%s %s %v", n.AttributePath, n.Operator, n.Value)
}

// LogicalAndNode represents a logical AND expression.
type LogicalAndNode struct {
	Left  Node
	Right Node
}

// Type returns the node type.
func (n *LogicalAndNode) Type() NodeType {
	return NodeLogicalAnd
}

// String returns the string representation of the node.
func (n *LogicalAndNode) String() string {
	return fmt.Sprintf("(%s and %s)", n.Left.String(), n.Right.String())
}

// LogicalOrNode represents a logical OR expression.
type LogicalOrNode struct {
	Left  Node
	Right Node
}

// Type returns the node type.
func (n *LogicalOrNode) Type() NodeType {
	return NodeLogicalOr
}

// String returns the string representation of the node.
func (n *LogicalOrNode) String() string {
	return fmt.Sprintf("(%s or %s)", n.Left.String(), n.Right.String())
}

// LogicalNotNode represents a logical NOT expression.
type LogicalNotNode struct {
	Operand Node
}

// Type returns the node type.
func (n *LogicalNotNode) Type() NodeType {
	return NodeLogicalNot
}

// String returns the string representation of the node.
func (n *LogicalNotNode) String() string {
	return fmt.Sprintf("not (%s)", n.Operand.String())
}

// ValuePathNode represents a value path filter (e.g., "emails[type eq 'work']").
type ValuePathNode struct {
	AttributePath string
	Filter        Node
}

// Type returns the node type.
func (n *ValuePathNode) Type() NodeType {
	return NodeValuePath
}

// String returns the string representation of the node.
func (n *ValuePathNode) String() string {
	return fmt.Sprintf("%s[%s]", n.AttributePath, n.Filter.String())
}

// AttributePath represents a parsed attribute path.
type AttributePath struct {
	URIPrefix     string // Optional schema URI prefix
	AttributeName string // Main attribute name
	SubAttribute  string // Optional sub-attribute
	ValueFilter   Node   // Optional value filter for multi-valued attributes
}

// ParseAttributePath parses an attribute path string.
func ParseAttributePath(path string) (*AttributePath, error) {
	ap := &AttributePath{}

	// Check for URI prefix (e.g., "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber")
	if idx := strings.LastIndex(path, ":"); idx > 0 && strings.HasPrefix(path, "urn:") {
		// Find the last colon that's part of the URI
		parts := strings.Split(path, ":")
		if len(parts) > 1 {
			// The last part after the URI is the attribute
			lastPart := parts[len(parts)-1]
			if !strings.Contains(lastPart, "/") {
				ap.URIPrefix = strings.Join(parts[:len(parts)-1], ":")
				path = lastPart
			}
		}
	}

	// Check for sub-attribute (e.g., "name.givenName")
	if idx := strings.Index(path, "."); idx > 0 {
		ap.AttributeName = path[:idx]
		ap.SubAttribute = path[idx+1:]
	} else {
		ap.AttributeName = path
	}

	return ap, nil
}

// String returns the string representation of the attribute path.
func (ap *AttributePath) String() string {
	var sb strings.Builder

	if ap.URIPrefix != "" {
		sb.WriteString(ap.URIPrefix)
		sb.WriteString(":")
	}

	sb.WriteString(ap.AttributeName)

	if ap.SubAttribute != "" {
		sb.WriteString(".")
		sb.WriteString(ap.SubAttribute)
	}

	return sb.String()
}

// FullPath returns the full attribute path including sub-attribute.
func (ap *AttributePath) FullPath() string {
	if ap.SubAttribute != "" {
		return ap.AttributeName + "." + ap.SubAttribute
	}
	return ap.AttributeName
}
