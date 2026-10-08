package oauth

import (
	"context"
	"errors"
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

	if err := s.CreateRefreshTokenSession(ctx, "refresh-sig", "", newRequest(client, subject)); err != nil {
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

// TestStorageRevocationAndRotation verifies that tokens record their
// request as the family, that revoking by request ID makes them inactive,
// and that rotation retires the exchanged refresh token.
func TestStorageRevocationAndRotation(t *testing.T) {
	_, s, client := newStorageClient(t)
	ctx := context.Background()

	req := newRequest(client, "user-1")
	if err := s.CreateAccessTokenSession(ctx, "acc-1", req); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}
	if err := s.CreateRefreshTokenSession(ctx, "ref-1", "acc-1", req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}
	if _, err := s.GetRefreshTokenSession(ctx, "ref-1", &fosite.DefaultSession{}); err != nil {
		t.Fatalf("refresh token before revocation: %v", err)
	}

	if err := s.RevokeRefreshToken(ctx, req.GetID()); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}
	if _, err := s.GetRefreshTokenSession(ctx, "ref-1", &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Errorf("refresh token after revoking its family error = %v, want ErrInactiveToken", err)
	}

	other := newRequest(client, "user-2")
	if err := s.CreateRefreshTokenSession(ctx, "ref-2", "", other); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}
	if err := s.RotateRefreshToken(ctx, other.GetID(), "ref-2"); err != nil {
		t.Fatalf("RotateRefreshToken: %v", err)
	}
	if _, err := s.GetRefreshTokenSession(ctx, "ref-2", &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Errorf("rotated refresh token error = %v, want ErrInactiveToken", err)
	}
}

// TestStorageRefreshAttachesToAccessToken verifies that a refresh token
// issued with its access token is recorded on that token's row.
func TestStorageRefreshAttachesToAccessToken(t *testing.T) {
	db, s, client := newStorageClient(t)
	ctx := context.Background()
	req := newRequest(client, "user-1")
	if err := s.CreateAccessTokenSession(ctx, "acc-1", req); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}
	if err := s.CreateRefreshTokenSession(ctx, "ref-1", "acc-1", req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}
	n, err := db.OAuthToken.Query().Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("token rows = %d, want 1 row holding both tokens", n)
	}
}
