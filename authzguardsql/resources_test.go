package authzguardsql

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grokify/guardsql"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/rebac/spicedb"
)

// Every entity and field is its own concrete resource, scoped to the
// organization.
func TestDefaultResourceBuilderConcreteResources(t *testing.T) {
	orgA, orgB := uuid.New(), uuid.New()
	a := DefaultResourceBuilder{OrgID: &orgA}
	b := DefaultResourceBuilder{OrgID: &orgB}

	salary := a.FieldResource("Salaries", "Salary")
	if salary.Type != ResourceTypeField || salary.ID == nil || salary.OrgID == nil || *salary.OrgID != orgA {
		t.Fatalf("field resource = %+v, want a guardsql_field with an ID in org A", salary)
	}
	if *salary.ID != a.FieldResourceID("salaries", "salary") {
		t.Error("field resource ID is not FieldResourceID, case-insensitively")
	}
	ids := map[uuid.UUID]string{}
	for name, id := range map[string]uuid.UUID{
		"salaries.salary":       a.FieldResourceID("salaries", "salary"),
		"salaries.name":         a.FieldResourceID("salaries", "name"),
		"people.salary":         a.FieldResourceID("people", "salary"),
		"entity salaries":       a.EntityResourceID("salaries"),
		"org B salaries.salary": b.FieldResourceID("salaries", "salary"),
		"a.b + c":               a.FieldResourceID("a.b", "c"),
		"a + b.c":               a.FieldResourceID("a", "b.c"),
	} {
		if other, dup := ids[id]; dup {
			t.Errorf("%s and %s share resource ID %s", name, other, id)
		}
		ids[id] = name
	}
	if e := a.EntityResource("salaries"); e.Type != ResourceTypeEntity || e.ID == nil || *e.ID != a.EntityResourceID("salaries") {
		t.Errorf("entity resource = %+v", e)
	}
}

// With SpiceDB, a grant on one field must not expose the entity's other
// fields, and grants in one organization must not apply in another.
func TestPolicyBuilderFieldLevelWithSpiceDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := spicedb.NewClient(ctx, spicedb.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	const schema = `
definition principal {}

definition guardsql_entity {
    relation reader: principal
    permission read = reader
}

definition guardsql_field {
    relation reader: principal
    permission read = reader
    permission list = reader
    permission sort = reader
}
`
	if err := client.WriteSchema(ctx, schema); err != nil {
		t.Fatal(err)
	}

	orgA, orgB := uuid.New(), uuid.New()
	analyst := uuid.New()
	builder := DefaultResourceBuilder{OrgID: &orgA}
	rel := func(typ authz.ResourceType, id uuid.UUID) *spicedb.Relationship {
		return &spicedb.Relationship{ResourceType: string(typ), ResourceID: id.String(), Relation: "reader",
			SubjectType: spicedb.TypePrincipal, SubjectID: analyst.String()}
	}
	if err := client.WriteRelationships(ctx, []*spicedb.Relationship{
		rel(ResourceTypeEntity, builder.EntityResourceID("salaries")),
		rel(ResourceTypeField, builder.FieldResourceID("salaries", "name")),
	}); err != nil {
		t.Fatal(err)
	}

	schemaDef := guardsql.Schema{Entities: map[string]guardsql.Entity{
		"salaries": {Fields: map[string]guardsql.Field{
			"name":   {Type: guardsql.FieldString, Selectable: true},
			"salary": {Type: guardsql.FieldNumber, Selectable: true},
		}},
	}}
	provider := spicedb.NewProvider(client)
	policy, err := PolicyBuilder{
		Authorizer: provider, Principal: authz.NewUserPrincipal(analyst),
		Schema: schemaDef, ResourceBuilder: builder,
	}.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg := guardsql.Config{Schema: schemaDef, Policy: policy}
	if _, err := cfg.Check("SELECT name FROM salaries"); err != nil {
		t.Errorf("granted field refused: %v", err)
	}
	if _, err := cfg.Check("SELECT salary FROM salaries"); err == nil {
		t.Error("salary selectable without a grant on that field")
	}

	_, err = PolicyBuilder{
		Authorizer: provider, Principal: authz.NewUserPrincipal(analyst),
		Schema: schemaDef, ResourceBuilder: DefaultResourceBuilder{OrgID: &orgB},
	}.Build(ctx)
	if err == nil {
		t.Error("org A's grants applied in org B")
	}
}
