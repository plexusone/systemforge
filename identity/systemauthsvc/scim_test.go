package systemauthsvc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/scimtoken"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

func scimService(t *testing.T, so *systemauthsvc.SCIMOptions) *systemauthsvc.Service {
	t.Helper()
	cfg := &systemauthsvc.Config{
		Issuer:   mpIssuer,
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		Clients: []systemauth.ClientConfig{{
			ID: "app", Type: "public", Name: "App",
			RedirectURIs:  []string{mpCallback},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", systemauthsvc.SCIMTokensScope},
		}},
		Features: systemauth.FeatureConfig{RequirePKCE: true},
	}
	svc, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{
		Dev:           true,
		SigningKey:    testKey(t),
		Logger:        discardLogger(),
		Migrate:       true,
		SCIM:          so,
		ServerOptions: []systemauth.Option{systemauth.WithSessionProvider(headerSession{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, svc)
	return svc
}

// addOrg creates an organization with owner as its owner.
func addOrg(t *testing.T, svc *systemauthsvc.Service, slug string, owner uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	db := svc.EntClient()
	org, err := db.Organization.Create().SetName(slug).SetSlug(slug).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.PrincipalMembership.Create().SetPrincipalID(owner).SetOrganizationID(org.ID).SetRole("owner").Save(ctx); err != nil {
		t.Fatal(err)
	}
	return org.ID
}

// scimUsers calls the SCIM Users endpoint.
func scimUsers(t *testing.T, svc *systemauthsvc.Service, token, method string, body any) (int, string) {
	t.Helper()
	w := callAPI(t, svc, token, method, systemauthsvc.SCIMPath+"/Users", body)
	return w.Code, w.Body.String()
}

func TestSCIMAuthenticatesStoredTenantTokens(t *testing.T) {
	svc := scimService(t, &systemauthsvc.SCIMOptions{})
	if svc.SCIMTokens() == nil {
		t.Fatal("SCIM token store not enabled")
	}
	alice := addManager(t, svc, "alice@example.com")
	bob := addManager(t, svc, "bob@example.com")
	acme := addOrg(t, svc, "acme", alice)
	beta := addOrg(t, svc, "beta", bob)

	// The organization owner issues a token through the management API.
	access := accessToken(t, svc, alice, systemauthsvc.SCIMTokensScope)
	w := callAPI(t, svc, access, http.MethodPost, "/api/v1/organizations/acme/scim-tokens", map[string]any{"description": "idp"})
	if w.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", w.Code, w.Body)
	}
	var issued scimtoken.Issued
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.Metadata.OrganizationID != acme {
		t.Fatalf("issued for %s, want %s", issued.Metadata.OrganizationID, acme)
	}
	// Alice cannot manage beta's tokens.
	if w := callAPI(t, svc, access, http.MethodPost, "/api/v1/organizations/beta/scim-tokens", map[string]any{}); w.Code != http.StatusForbidden {
		t.Fatalf("issue for another organization: %d %s", w.Code, w.Body)
	}
	// The management API needs the scope.
	plain := accessToken(t, svc, alice, "profile")
	if w := callAPI(t, svc, plain, http.MethodGet, "/api/v1/organizations/acme/scim-tokens", nil); w.Code != http.StatusForbidden {
		t.Fatalf("management without scope: %d", w.Code)
	}

	user := map[string]any{"schemas": []string{scim.SchemaUser}, "userName": "ada@example.com"}
	if code, body := scimUsers(t, svc, issued.Token, http.MethodPost, user); code != http.StatusCreated {
		t.Fatalf("create user with tenant token: %d %s", code, body)
	}
	if code, body := scimUsers(t, svc, issued.Token, http.MethodGet, nil); code != http.StatusOK || !strings.Contains(body, "ada@example.com") {
		t.Fatalf("list users: %d %s", code, body)
	}

	// Beta's token sees none of acme's users.
	betaToken, err := svc.SCIMTokens().Issue(t.Context(), bob, beta, scimtoken.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if code, body := scimUsers(t, svc, betaToken.Token, http.MethodGet, nil); code != http.StatusOK || strings.Contains(body, "ada@example.com") {
		t.Fatalf("tenant B lists tenant A's user: %d %s", code, body)
	}

	// No platform credentials unless configured; access tokens are not SCIM credentials.
	if code, _ := scimUsers(t, svc, access, http.MethodGet, nil); code != http.StatusUnauthorized {
		t.Fatalf("access token as SCIM credential: %d", code)
	}
	if code, _ := scimUsers(t, svc, "", http.MethodGet, nil); code != http.StatusUnauthorized {
		t.Fatalf("no credential: %d", code)
	}
}

func TestSCIMIsOffByDefault(t *testing.T) {
	svc := scimService(t, nil)
	if svc.SCIMTokens() != nil {
		t.Fatal("SCIM token store enabled without SCIMOptions")
	}
	for _, p := range []string{systemauthsvc.SCIMPath + "/Users", "/api/v1/organizations/acme/scim-tokens"} {
		if w := callAPI(t, svc, "", http.MethodGet, p, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
}
