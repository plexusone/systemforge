package systemauth

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
)

// tasksVocab declares a second application.
type tasksVocab struct{}

func (tasksVocab) App() string { return "tasks" }
func (tasksVocab) Roles() authz.RolePermissions {
	return authz.RolePermissions{"viewer": {"task.read"}, "admin": {"task.read", "task.admin"}}
}
func (tasksVocab) Hierarchy() authz.RoleHierarchy {
	return authz.RoleHierarchy{"viewer": 10, "admin": 40}
}
func (tasksVocab) Scopes() []string      { return nil }
func (tasksVocab) SpiceDBSchema() string { return "" }

// entitlements is a switchable entitlement source: every organization is
// entitled to the applications in apps.
type entitlements struct {
	mu   sync.Mutex
	apps map[string]bool
}

func (e *entitlements) set(apps ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.apps = map[string]bool{}
	for _, a := range apps {
		e.apps[a] = true
	}
}

func (e *entitlements) option(*authz.VocabularyRegistry) approle.Option {
	return approle.WithEntitlementGrants(func(context.Context, uuid.UUID) (map[string]approle.Grant, error) {
		e.mu.Lock()
		defer e.mu.Unlock()
		out := map[string]approle.Grant{}
		for a := range e.apps {
			out[a] = approle.Grant{}
		}
		return out, nil
	})
}

// appsIn returns the apps map of the organization id in an orgs claim.
func appsIn(t *testing.T, orgs []map[string]any, id string) map[string]any {
	t.Helper()
	for _, o := range orgs {
		if o["id"] == id {
			apps, _ := o["apps"].(map[string]any)
			return apps
		}
	}
	t.Fatalf("organization %s not in %v", id, orgs)
	return nil
}

// TestOrgsClaimAppsIsTheEntitlement pins that the orgs claim's "apps" is
// where product entitlements reach tokens (ADR-007): an application
// appears only while the organization is entitled to it, with the
// principal's role in it, in the ID token, the JWT access token, userinfo
// and the memberships endpoint alike. A stored role in an application the
// organization is no longer entitled to is not carried.
func TestOrgsClaimAppsIsTheEntitlement(t *testing.T) {
	ent := &entitlements{}
	ent.set("notes", "tasks")
	f := newOrgsFixtureWith(t, ent.option, notesVocab{}, tasksVocab{})
	ctx := context.Background()
	team := f.join(t, "acme", "member", 0)
	for _, app := range []string{"notes", "tasks"} {
		if _, err := f.roles.Assign(ctx, approle.AssignInput{OrganizationID: team.ID, PrincipalID: f.principal, Application: app, Role: "viewer"}); err != nil {
			t.Fatalf("assign %s: %v", app, err)
		}
	}

	check := func(label string, want map[string]string, wantPersonal map[string]string) {
		t.Helper()
		tokens := f.tokens(t, "openid")
		at := tokens["access_token"].(string)
		_, info := userinfo(t, f.s, dpopAuth(t, at), http.MethodGet, nil)
		code, page := memberships(t, f.s, at, "")
		if code != http.StatusOK {
			t.Fatalf("%s: memberships: %d", label, code)
		}
		pageOrgs := make([]map[string]any, 0, len(page.Orgs))
		for _, o := range page.Orgs {
			apps := map[string]any{}
			for k, v := range o.Apps {
				apps[k] = v
			}
			pageOrgs = append(pageOrgs, map[string]any{"id": o.ID, "apps": apps})
		}
		sources := map[string][]map[string]any{
			"id token":     orgsOf(t, verifyJWT(t, f.s, tokens["id_token"].(string))),
			"access token": orgsOf(t, verifyJWT(t, f.s, at)),
			"userinfo":     orgsOf(t, info),
			"memberships":  pageOrgs,
		}
		for name, orgs := range sources {
			for id, w := range map[string]map[string]string{team.ID.String(): want, f.personal.ID.String(): wantPersonal} {
				got := appsIn(t, orgs, id)
				if len(got) != len(w) {
					t.Errorf("%s: %s apps for %s = %v, want %v", label, name, id, got, w)
					continue
				}
				for app, role := range w {
					if got[app] != role {
						t.Errorf("%s: %s apps for %s = %v, want %v", label, name, id, got, w)
					}
				}
			}
		}
	}

	check("entitled to both", map[string]string{"notes": "viewer", "tasks": "viewer"},
		map[string]string{"notes": "admin", "tasks": "admin"})

	// Losing the tasks entitlement removes it from every claim, although the
	// stored role remains; the owner's implicit admin goes with it.
	ent.set("notes")
	check("entitled to notes", map[string]string{"notes": "viewer"}, map[string]string{"notes": "admin"})

	// With no entitlement the organization is still listed, with no apps.
	ent.set()
	check("entitled to nothing", map[string]string{}, map[string]string{})
}
