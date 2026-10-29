package systemauth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent/enttest"
)

// checkEmbeddedRevoke expects EmbeddedOAuthProvider.Revoke to revoke the
// token family of the access or refresh token it is given, and to report
// an unknown or already revoked token rather than succeed silently.
func checkEmbeddedRevoke(t *testing.T, newServer func(t *testing.T) *Server) {
	t.Helper()
	ctx := context.Background()

	issue := func(t *testing.T, s *Server) (accessToken, refreshToken string) {
		t.Helper()
		code := authorizeCode(t, s, "openid offline_access", headerUser(newPrincipal(t, s)))
		tokens := exchangeCode(t, s, code)
		at, _ := tokens["access_token"].(string)
		rt, _ := tokens["refresh_token"].(string)
		if at == "" || rt == "" {
			t.Fatalf("missing tokens: %v", tokens)
		}
		return at, rt
	}
	refreshActive := func(s *Server, rt string) bool {
		_, _, err := s.oauth2.IntrospectToken(ctx, rt, fosite.RefreshToken, s.Session(""))
		return err == nil
	}

	t.Run("access token", func(t *testing.T) {
		s := newServer(t)
		p := NewEmbeddedOAuthProvider(s)
		at, rt := issue(t, s)
		if err := p.Revoke(ctx, at, "access_token"); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if introspectActive(t, s, at) {
			t.Error("access token still active after Revoke")
		}
		if refreshActive(s, rt) {
			t.Error("refresh token of the family still active after Revoke")
		}
		if info, err := p.Introspect(ctx, at, ""); err != nil || info.Active {
			t.Errorf("Introspect after Revoke = %+v, %v; want inactive", info, err)
		}
		if err := p.Revoke(ctx, at, ""); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("second Revoke = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("refresh token", func(t *testing.T) {
		s := newServer(t)
		p := NewEmbeddedOAuthProvider(s)
		at, rt := issue(t, s)
		if err := p.Revoke(ctx, rt, "refresh_token"); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if refreshActive(s, rt) {
			t.Error("refresh token still active after Revoke")
		}
		if introspectActive(t, s, at) {
			t.Error("access token of the family still active after Revoke")
		}
	})

	t.Run("unknown token", func(t *testing.T) {
		p := NewEmbeddedOAuthProvider(newServer(t))
		for _, tok := range []string{"", "not-a-token", "ory_at_abc.def"} {
			if err := p.Revoke(ctx, tok, ""); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("Revoke(%q) = %v, want ErrInvalidToken", tok, err)
			}
		}
	})
}

func TestEmbeddedOAuthProviderRevokeMemory(t *testing.T) {
	checkEmbeddedRevoke(t, func(t *testing.T) *Server { return newRefreshTestServer(t) })
}

func TestEmbeddedOAuthProviderRevokeEnt(t *testing.T) {
	checkEmbeddedRevoke(t, func(t *testing.T) *Server {
		client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		})
		owner := createTestOwner(t, client)
		return newRefreshTestServer(t, WithStorage(NewEntStorage(client, WithDefaultOwner(owner))))
	})
}
