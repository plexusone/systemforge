package filter

import (
	"fmt"
	"strconv"
	"strings"
)

// MaxDepth is the deepest nesting of parentheses, not and value-path
// brackets a filter may have; a deeper one is refused rather than parsed,
// so a request cannot make the parser recurse without bound.
const MaxDepth = 32

// Parser parses SCIM filter expressions into an AST.
type Parser struct {
	lexer    *Lexer
	curToken Token
	depth    int
}

// NewParser creates a new parser for the given input.
func NewParser(input string) *Parser {
	p := &Parser{
		lexer: NewLexer(input),
	}
	p.nextToken()
	return p
}

// Parse parses the filter expression and returns the AST.
func (p *Parser) Parse() (Node, error) {
	if p.curToken.Type == TokenEOF {
		return nil, nil
	}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	// The whole input must be one expression: trailing tokens are an
	// error, not ignored.
	if p.curToken.Type != TokenEOF {
		return nil, fmt.Errorf("unexpected %s after the filter expression", p.curToken.Value)
	}
	return node, nil
}

// enter records one more level of nesting and refuses one beyond MaxDepth.
func (p *Parser) enter() error {
	p.depth++
	if p.depth > MaxDepth {
		return fmt.Errorf("filter is nested more than %d levels deep", MaxDepth)
	}
	return nil
}

func (p *Parser) leave() { p.depth-- }

// nextToken advances to the next token.
func (p *Parser) nextToken() {
	p.curToken = p.lexer.NextToken()
}

// parseOr parses OR expressions.
func (p *Parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}

	for p.curToken.Type == TokenOr {
		p.nextToken() // consume 'or'
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &LogicalOrNode{Left: left, Right: right}
	}

	return left, nil
}

// parseAnd parses AND expressions.
func (p *Parser) parseAnd() (Node, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}

	for p.curToken.Type == TokenAnd {
		p.nextToken() // consume 'and'
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &LogicalAndNode{Left: left, Right: right}
	}

	return left, nil
}

// parseNot parses NOT expressions.
func (p *Parser) parseNot() (Node, error) {
	if p.curToken.Type == TokenNot {
		p.nextToken() // consume 'not'

		// NOT must be followed by a parenthesized expression
		if p.curToken.Type != TokenLeftParen {
			return nil, fmt.Errorf("expected '(' after 'not', got %s", p.curToken.Value)
		}

		operand, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}

		return &LogicalNotNode{Operand: operand}, nil
	}

	return p.parsePrimary()
}

// parsePrimary parses primary expressions (comparisons, groupings, value paths).
func (p *Parser) parsePrimary() (Node, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	// Handle parenthesized expressions
	if p.curToken.Type == TokenLeftParen {
		p.nextToken() // consume '('
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.curToken.Type != TokenRightParen {
			return nil, fmt.Errorf("expected ')', got %s", p.curToken.Value)
		}
		p.nextToken() // consume ')'
		return node, nil
	}

	// Must be an attribute path followed by operator
	if p.curToken.Type != TokenIdentifier {
		return nil, fmt.Errorf("expected attribute path, got %s", p.curToken.Value)
	}

	attrPath := p.curToken.Value
	p.nextToken()

	// Check for value path filter (e.g., "emails[type eq 'work']")
	if p.curToken.Type == TokenLeftBracket {
		p.nextToken() // consume '['
		filter, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.curToken.Type != TokenRightBracket {
			return nil, fmt.Errorf("expected ']', got %s", p.curToken.Value)
		}
		p.nextToken() // consume ']'

		// Check if there's a sub-attribute after the filter
		if p.curToken.Type == TokenIdentifier && strings.HasPrefix(p.curToken.Value, ".") {
			// There's a sub-attribute selection after the filter
			subAttr := strings.TrimPrefix(p.curToken.Value, ".")
			p.nextToken()
			return &ValuePathNode{
				AttributePath: attrPath + "." + subAttr,
				Filter:        filter,
			}, nil
		}

		return &ValuePathNode{
			AttributePath: attrPath,
			Filter:        filter,
		}, nil
	}

	// Must be an operator
	if p.curToken.Type != TokenOperator {
		return nil, fmt.Errorf("expected operator, got %s", p.curToken.Value)
	}

	op := Operator(strings.ToLower(p.curToken.Value))
	p.nextToken()

	// pr (present) operator has no value
	if op == OpPresent {
		return &ComparisonNode{
			AttributePath: attrPath,
			Operator:      op,
		}, nil
	}

	// Parse the comparison value
	value, err := p.parseValue()
	if err != nil {
		return nil, err
	}

	return &ComparisonNode{
		AttributePath: attrPath,
		Operator:      op,
		Value:         value,
	}, nil
}

// parseValue parses a comparison value.
func (p *Parser) parseValue() (any, error) {
	switch p.curToken.Type {
	case TokenString:
		value := p.curToken.Value
		p.nextToken()
		return value, nil

	case TokenNumber:
		value := p.curToken.Value
		p.nextToken()
		// Try to parse as int first, then float
		if i, err := strconv.ParseInt(value, 10, 64); err == nil {
			return i, nil
		}
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f, nil
		}
		return value, nil

	case TokenBoolean:
		value := p.curToken.Literal.(bool)
		p.nextToken()
		return value, nil

	case TokenNull:
		p.nextToken()
		return nil, nil

	default:
		return nil, fmt.Errorf("expected value, got %s", p.curToken.Value)
	}
}

// ParseFilter parses a SCIM filter string and returns the AST.
func ParseFilter(filter string) (Node, error) {
	if filter == "" {
		return nil, nil
	}
	parser := NewParser(filter)
	return parser.Parse()
}
