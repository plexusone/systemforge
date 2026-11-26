package systemauthsvc

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"entgo.io/ent/dialect"

	"github.com/plexusone/systemforge/identity/ent"
	entmigrate "github.com/plexusone/systemforge/identity/ent/migrate"
)

// ErrSchemaBehind is returned when the database lacks tables or columns this
// version of SystemForge needs. Starting anyway would fail later and
// elsewhere, such as the first sign-up that touches a new column, so New
// refuses to start instead; run the migration (see CheckSchema).
var ErrSchemaBehind = errors.New("systemauthsvc: the database schema is behind this version")

// maxListed bounds how many missing tables or columns an error lists.
const maxListed = 10

// CheckSchema reports whether the database has every table and column of the
// identity schema, without changing it. It returns an error wrapping
// ErrSchemaBehind that names what is missing and how to fix it, and nil when
// the schema is complete or the dialect is unknown (nothing to compare with).
//
// It compares names only. It does not check types, indexes or the PostgreSQL
// objects Ent cannot express, so a database that passes is not proof that the
// migration ran, but one that fails certainly needs it.
func CheckSchema(ctx context.Context, client *ent.Client, dialectName string) error {
	present, err := presentColumns(ctx, client, dialectName)
	if err != nil {
		return err
	}
	if present == nil {
		return nil
	}
	var tables, columns []string
	for _, t := range entmigrate.Tables {
		if t.View {
			continue
		}
		have, ok := present[t.Name]
		if !ok {
			tables = append(tables, t.Name)
			continue
		}
		for _, c := range t.Columns {
			if !have[c.Name] {
				columns = append(columns, t.Name+"."+c.Name)
			}
		}
	}
	if len(tables) == 0 && len(columns) == 0 {
		return nil
	}
	sort.Strings(tables)
	sort.Strings(columns)
	var parts []string
	if len(tables) > 0 {
		parts = append(parts, "missing tables: "+listed(tables))
	}
	if len(columns) > 0 {
		parts = append(parts, "missing columns: "+listed(columns))
	}
	return fmt.Errorf("%w (%s); run the migration first: `systemauth migrate`, `systemauth --migrate serve`, or systemauthsvc.Migrate",
		ErrSchemaBehind, strings.Join(parts, "; "))
}

// listed joins names, cutting a long list.
func listed(names []string) string {
	if len(names) <= maxListed {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:maxListed], ", "), len(names)-maxListed)
}

// presentColumns maps each table of the current schema to its columns, or
// returns nil for a dialect it cannot read.
func presentColumns(ctx context.Context, client *ent.Client, dialectName string) (map[string]map[string]bool, error) {
	var query string
	switch dialectName {
	case dialect.Postgres:
		query = `SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = current_schema()`
	case dialect.SQLite:
		query = `SELECT m.name, p.name FROM sqlite_master m JOIN pragma_table_info(m.name) p WHERE m.type = 'table'`
	default:
		return nil, nil
	}
	rows, err := client.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("reading the database schema: %w", err)
	}
	present := map[string]map[string]bool{}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			return nil, errors.Join(fmt.Errorf("reading the database schema: %w", err), rows.Close())
		}
		if present[table] == nil {
			present[table] = map[string]bool{}
		}
		present[table][column] = true
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(fmt.Errorf("reading the database schema: %w", err), rows.Close())
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("reading the database schema: %w", err)
	}
	return present, nil
}

// CheckMigrations opens the configured database, runs CheckSchema and closes
// it, so a deploy can verify the schema before starting the new version.
func CheckMigrations(ctx context.Context, cfg *Config) (err error) {
	if cfg.Database == nil {
		return errors.New("database configuration required to check the schema")
	}
	db, err := OpenDatabase(cfg.Database)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := db.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing database: %w", cerr)
		}
	}()
	return CheckSchema(ctx, db.Client, db.Dialect)
}
