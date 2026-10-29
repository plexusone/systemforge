package systemauth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
)

// TestTokenFamilyRevocationEvents verifies that revoking a token family,
// for a deactivated principal or past the family's absolute lifetime, is
// recorded with its reason.
func TestTokenFamilyRevocationEvents(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	events := &eventCapture{}
	s := newRefreshTestServer(t, WithStorage(NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))), WithAuditEmitter(events))
	p, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier("kim@example.com").SetDisplayName("Kim").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tokens := exchangeCode(t, s, authorizeCode(t, s, "openid offline_access", headerUser(p.ID.String())))
	rt, _ := tokens["refresh_token"].(string)
	if err := db.Principal.UpdateOneID(p.ID).SetActive(false).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if status, body := refresh(t, s, rt); status == http.StatusOK {
		t.Fatalf("refresh for a deactivated principal: %v", body)
	}
	revoked := events.find(EventTokenFamilyRevoked, audit.OutcomeSuccess)
	if len(revoked) != 1 || revoked[0].Details["reason"] != "principal_inactive" || revoked[0].Details["subject"] != p.ID.String() || revoked[0].Resource.Identifier == "" {
		t.Errorf("family revocation events: %+v", revoked)
	}
	refused := events.find(EventTokenRefused, audit.OutcomeFailure)
	if len(refused) != 1 || refused[0].Details["reason"] != "principal_inactive" || refused[0].Details["client_id"] != "spa" || refused[0].Details["error"] != "invalid_grant" {
		t.Errorf("refusal events: %+v", refused)
	}

	ar := fosite.NewAccessRequest(&Session{DefaultSession: &openid.DefaultSession{}, FamilyIssuedAt: time.Now().Add(-31 * 24 * time.Hour)})
	ar.GrantTypes = fosite.Arguments{"refresh_token"}
	ar.ID = uuid.NewString()
	if err := s.applyTokenFamilyLifetime(ctx, ar); err == nil {
		t.Fatal("expired family accepted")
	}
	revoked = events.find(EventTokenFamilyRevoked, audit.OutcomeSuccess)
	if len(revoked) != 2 || revoked[1].Details["reason"] != "token_family_lifetime" || revoked[1].Resource.Identifier != ar.ID {
		t.Errorf("lifetime revocation events: %+v", revoked)
	}
}

// TestAuditEmitterDefault verifies that events are discarded without an
// emitter and that a nil emitter is accepted.
func TestAuditEmitterDefault(t *testing.T) {
	for _, opts := range [][]Option{nil, {WithAuditEmitter(nil)}} {
		s := newRefreshTestServer(t, opts...)
		if _, ok := s.audit.(audit.NopEmitter); !ok {
			t.Errorf("default emitter = %T", s.audit)
		}
	}
}
