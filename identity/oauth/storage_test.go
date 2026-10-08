package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/oauthauthcode"
	"github.com/plexusone/systemforge/identity/ent/oauthtoken"
	"github.com/plexusone/systemforge/identity/ent/principal"

	_ "github.com/mattn/go-sqlite3"
)

// newStorageClient opens an in-memory database with one OAuth app owned by
// a service principal and returns the storage and a Fosite client for it.
func newStorageClient(t *testing.T) (*ent.Client, *Storage, *Client) {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	ctx := context.Background()
	owner, err := db.Principal.Create().
		SetType(principal.TypeService).
		SetIdentifier("owner-" + uuid.NewString()[:8]).
		SetDisplayName("Owner").
		Save(ctx)
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	app, err := db.OAuthApp.Create().
		SetClientID("app-" + uuid.NewString()[:8]).
		SetName("App").
		SetOwnerID(owner.ID).
		Save(ctx)
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	s := NewStorage(db)
	return db, s, &Client{app: app, storage: s}
}

func newRequest(client *Client, subject string) *fosite.Request {
	req := fosite.NewRequest()
	req.Client = client
	req.Session = &fosite.DefaultSession{
		Subject: subject,
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:  time.Now().Add(time.Hour),
			fosite.RefreshToken: time.Now().Add(24 * time.Hour),
		},
	}
	return req
}

// TestStorageRecordsSubject verifies that tokens and authorization codes
// record the authenticated subject, including subjects that are not UUIDs,
// which were previously dropped.
func TestStorageRecordsSubject(t *testing.T) {
	const subject = "human:not-a-uuid"
	db, s, client := newStorageClient(t)
	ctx := context.Background()

	if err := s.CreateAccessTokenSession(ctx, "access-sig", newRequest(client, subject)); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}
	tok, err := db.OAuthToken.Query().Where(oauthtoken.AccessTokenSignatureEQ(hashToken("access-sig"))).Only(ctx)
	if err != nil {
		t.Fatalf("query access token: %v", err)
	}
	if tok.Subject != subject {
		t.Errorf("access token subject = %q, want %q", tok.Subject, subject)
	}

	if err := s.CreateRefreshTokenSession(ctx, "refresh-sig", newRequest(client, subject)); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}
	rt, err := db.OAuthToken.Query().Where(oauthtoken.RefreshTokenSignatureEQ(hashToken("refresh-sig"))).Only(ctx)
	if err != nil {
		t.Fatalf("query refresh token: %v", err)
	}
	if rt.Subject != subject {
		t.Errorf("refresh token subject = %q, want %q", rt.Subject, subject)
	}

	if err := s.CreateAuthorizeCodeSession(ctx, "code", newRequest(client, subject)); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}
	code, err := db.OAuthAuthCode.Query().Where(oauthauthcode.CodeSignatureEQ(hashToken("code"))).Only(ctx)
	if err != nil {
		t.Fatalf("query auth code: %v", err)
	}
	if code.Subject != subject {
		t.Errorf("auth code subject = %q, want %q", code.Subject, subject)
	}

	// client_credentials tokens carry no subject.
	if err := s.CreateAccessTokenSession(ctx, "cc-sig", newRequest(client, "")); err != nil {
		t.Fatalf("CreateAccessTokenSession (client credentials): %v", err)
	}
	cc, err := db.OAuthToken.Query().Where(oauthtoken.AccessTokenSignatureEQ(hashToken("cc-sig"))).Only(ctx)
	if err != nil {
		t.Fatalf("query client-credentials token: %v", err)
	}
	if cc.Subject != "" {
		t.Errorf("client-credentials subject = %q, want empty", cc.Subject)
	}
}
