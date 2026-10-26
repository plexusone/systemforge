package filter

import (
	"fmt"
	"strings"
	"unicode"
)

// TokenType represents the type of a lexical token.
type TokenType int

const (
	TokenEOF TokenType = iota
	TokenIdentifier
	TokenString
	TokenNumber
	TokenBoolean
	TokenNull
	TokenOperator
	TokenAnd
	TokenOr
	TokenNot
	TokenLeftParen
	TokenRightParen
	TokenLeftBracket
	TokenRightBracket
	// TokenIllegal is a character that starts no token; the parser
	// refuses it.
	TokenIllegal
)

// Token represents a lexical token.
type Token struct {
	Type    TokenType
	Value   string
	Literal any // The parsed literal value for strings, numbers, booleans
}

// String returns a string representation of the token.
func (t Token) String() string {
	return fmt.Sprintf("Token(%d, %q)", t.Type, t.Value)
}

// Lexer tokenizes a SCIM filter expression.
type Lexer struct {
	input   string
	pos     int
	readPos int
	ch      byte
}

// NewLexer creates a new lexer for the given input.
func NewLexer(input string) *Lexer {
	l := &Lexer{input: input}
	l.readChar()
	return l
}

// readChar reads the next character.
func (l *Lexer) readChar() {
	if l.readPos >= len(l.input) {
		l.ch = 0
	} else {
		l.ch = l.input[l.readPos]
	}
	l.pos = l.readPos
	l.readPos++
}

// peekChar returns the next character without advancing.
func (l *Lexer) peekChar() byte {
	if l.readPos >= len(l.input) {
		return 0
	}
	return l.input[l.readPos]
}

// NextToken returns the next token from the input.
func (l *Lexer) NextToken() Token {
	l.skipWhitespace()

	var tok Token

	switch l.ch {
	case 0:
		if l.pos < len(l.input) {
			// A NUL byte inside the input is not its end.
			tok = Token{Type: TokenIllegal, Value: "\x00"}
			l.readChar()
			break
		}
		tok = Token{Type: TokenEOF, Value: ""}
	case '(':
		tok = Token{Type: TokenLeftParen, Value: "("}
		l.readChar()
	case ')':
		tok = Token{Type: TokenRightParen, Value: ")"}
		l.readChar()
	case '[':
		tok = Token{Type: TokenLeftBracket, Value: "["}
		l.readChar()
	case ']':
		tok = Token{Type: TokenRightBracket, Value: "]"}
		l.readChar()
	case '"', '\'':
		tok = l.readString()
	default:
		if isLetter(l.ch) {
			return l.readIdentifier()
		} else if isDigit(l.ch) || l.ch == '-' {
			return l.readNumber()
		} else {
			tok = Token{Type: TokenIllegal, Value: string(l.ch)}
			l.readChar()
		}
	}

	return tok
}

// skipWhitespace skips whitespace characters.
func (l *Lexer) skipWhitespace() {
	for l.ch == ' ' || l.ch == '\t' || l.ch == '\n' || l.ch == '\r' {
		l.readChar()
	}
}

// readString reads a quoted string.
func (l *Lexer) readString() Token {
	quote := l.ch // remember the opening quote character
	l.readChar()  // skip opening quote
	start := l.pos

	for l.ch != quote && l.ch != 0 {
		if l.ch == '\\' {
			l.readChar() // skip escape character
		}
		l.readChar()
	}

	value := l.input[start:l.pos]
	// Unescape the string
	value = unescapeString(value)

	l.readChar() // skip closing quote

	return Token{Type: TokenString, Value: value, Literal: value}
}

// readIdentifier reads an identifier or keyword.
func (l *Lexer) readIdentifier() Token {
	start := l.pos

	// Read identifier characters (letters, digits, underscores, dots, colons for URIs)
	for isIdentChar(l.ch) {
		l.readChar()
	}

	value := l.input[start:l.pos]
	tokenType := lookupIdent(value)

	tok := Token{Type: tokenType, Value: value}

	// Parse literal values
	switch value {
	case "true":
		tok.Literal = true
	case "false":
		tok.Literal = false
	case "null":
		tok.Literal = nil
	}

	return tok
}

// readNumber reads a numeric literal.
func (l *Lexer) readNumber() Token {
	start := l.pos

	if l.ch == '-' {
		l.readChar()
	}

	for isDigit(l.ch) {
		l.readChar()
	}

	// Check for decimal
	if l.ch == '.' && isDigit(l.peekChar()) {
		l.readChar() // consume '.'
		for isDigit(l.ch) {
			l.readChar()
		}
	}

	// Check for exponent
	if l.ch == 'e' || l.ch == 'E' {
		l.readChar()
		if l.ch == '+' || l.ch == '-' {
			l.readChar()
		}
		for isDigit(l.ch) {
			l.readChar()
		}
	}

	value := l.input[start:l.pos]
	return Token{Type: TokenNumber, Value: value}
}

// lookupIdent determines if an identifier is a keyword.
func lookupIdent(ident string) TokenType {
	lower := strings.ToLower(ident)
	switch lower {
	case "and":
		return TokenAnd
	case "or":
		return TokenOr
	case "not":
		return TokenNot
	case "true", "false":
		return TokenBoolean
	case "null":
		return TokenNull
	case "eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le", "pr":
		return TokenOperator
	default:
		return TokenIdentifier
	}
}

// isLetter returns true if the character is a letter.
func isLetter(ch byte) bool {
	return unicode.IsLetter(rune(ch)) || ch == '_'
}

// isDigit returns true if the character is a digit.
func isDigit(ch byte) bool {
	return unicode.IsDigit(rune(ch))
}

// isIdentChar returns true if the character can be part of an identifier.
func isIdentChar(ch byte) bool {
	return isLetter(ch) || isDigit(ch) || ch == '.' || ch == ':' || ch == '-' || ch == '_'
}

// unescapeString handles escape sequences in a string.
func unescapeString(s string) string {
	var result strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"':
				result.WriteByte('"')
			case '\\':
				result.WriteByte('\\')
			case 'n':
				result.WriteByte('\n')
			case 'r':
				result.WriteByte('\r')
			case 't':
				result.WriteByte('\t')
			default:
				result.WriteByte(s[i+1])
			}
			i += 2
		} else {
			result.WriteByte(s[i])
			i++
		}
	}
	return result.String()
}
