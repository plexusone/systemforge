package spicedb

import (
	"testing"

	"github.com/google/uuid"
)

func TestAppRoleRelationship(t *testing.T) {
	principalID, orgID := uuid.New(), uuid.New()
	rel, err := appRoleRelationship(principalID, orgID, "notes", "maintainer")
	if err != nil {
		t.Fatal(err)
	}
	if rel.ResourceType != "notes_org" || rel.ResourceID != orgID.String() || rel.Relation != "maintainer" ||
		rel.SubjectType != TypePrincipal || rel.SubjectID != principalID.String() {
		t.Errorf("relationship = %+v", rel)
	}
	for _, app := range []string{"", "Notes", "notes_org", "a", "organization#x", "9lives"} {
		if _, err := appRoleRelationship(principalID, orgID, app, "viewer"); err == nil {
			t.Errorf("application %q accepted", app)
		}
	}
	if _, err := appRoleRelationship(principalID, orgID, "notes", ""); err == nil {
		t.Error("empty role accepted")
	}
}
