package spicedb

import (
	"testing"

	"github.com/authzed/spicedb/pkg/schemadsl/compiler"
	"github.com/authzed/spicedb/pkg/schemadsl/input"

	"github.com/plexusone/systemforge/authz"
)

// TestResourceSchemaComposesWithBase compiles the resource helper's output
// after the base schema, so a change to either that breaks the other fails
// without a SpiceDB instance.
func TestResourceSchemaComposesWithBase(t *testing.T) {
	schema := authz.BaseSpiceDBSchema + ResourceSchema("myapp_project")
	if _, err := compiler.Compile(compiler.InputSchema{Source: input.Source("test"), SchemaString: schema}, compiler.AllowUnprefixedObjectType()); err != nil {
		t.Fatalf("composed schema does not compile: %v", err)
	}
}

// TestResourceRoleFragmentComposesWithBase compiles the standard
// collaborator-able definition after the base schema, and checks that it
// passes the vocabulary rules for an application of that name.
func TestResourceRoleFragmentComposesWithBase(t *testing.T) {
	fragment := authz.ResourceRoleFragment("myapp_project")
	if err := authz.ValidateAppSchema("myapp", fragment); err != nil {
		t.Fatalf("ValidateAppSchema: %v", err)
	}
	schema := authz.BaseSpiceDBSchema + "\n" + fragment
	if _, err := compiler.Compile(compiler.InputSchema{Source: input.Source("test"), SchemaString: schema}, compiler.AllowUnprefixedObjectType()); err != nil {
		t.Fatalf("composed schema does not compile: %v", err)
	}
}
