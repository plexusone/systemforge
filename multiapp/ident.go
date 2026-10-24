package multiapp

import (
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// quoteIdent quotes name as a single SQL identifier. Names reaching it have
// passed checkName, so quoting is a second line of defence, not the only one.
func quoteIdent(name string) string {
	return pgx.Identifier{name}.Sanitize()
}

// quoteQualified quotes schema.name as a schema-qualified identifier.
func quoteQualified(schema, name string) string {
	return pgx.Identifier{schema, name}.Sanitize()
}

// quoteLiteral quotes s as a SQL string literal.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, "\x00", ""), "'", "''") + "'"
}

// checkName refuses a schema, role, table or database name that is not a
// plain lowercase identifier (see isValidSchemaName). kind names the field
// in the error.
func checkName(kind, name string) error {
	if !isValidSchemaName(name) {
		return fmt.Errorf("multiapp: invalid %s name %q: use 1-63 lowercase letters, digits and underscores, starting with a letter or underscore", kind, name)
	}
	return nil
}
