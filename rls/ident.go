package rls

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// quoteIdent quotes a name, optionally schema-qualified (schema.table), as
// SQL identifiers, so a table, column, policy or role name is never read as
// SQL. Quoted identifiers are case-sensitive: pass names as they are stored
// (unquoted names are stored in lower case).
func quoteIdent(name string) string {
	return pgx.Identifier(strings.Split(name, ".")).Sanitize()
}

// quoteLiteral quotes s as a SQL string literal.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, "\x00", ""), "'", "''") + "'"
}

// settingName matches a custom configuration parameter (class.name), the
// form a session variable for RLS takes.
var settingName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)

// checkSettingName refuses a session variable name that is not a plain
// custom parameter name, before it is used in a statement that cannot take
// it as a parameter (RESET).
func checkSettingName(name string) error {
	if !settingName.MatchString(name) {
		return fmt.Errorf("rls: invalid session variable name %q", name)
	}
	return nil
}

// tenantPolicyName is the name of the tenant isolation policy of table: the
// unqualified table name with a suffix.
func tenantPolicyName(table string) string {
	parts := strings.Split(table, ".")
	return parts[len(parts)-1] + "_tenant_isolation"
}
