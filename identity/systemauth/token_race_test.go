package systemauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent/enttest"
)

// Two concurrent token requests with the same code or refresh token can both
// read it as valid before either writes. These wrappers reproduce that
// deterministically: their reads report a used code or a rotated refresh
// token as still valid, as a read taken just before the other request's write
// would, so the second request reaches the write and only the storage's
// conditional update can refuse it.

type staleMemoryReads struct{ *MemoryStorage }

func (s staleMemoryReads) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	return staleCode(s.MemoryStorage.GetAuthorizeCodeSession(ctx, code, session))
}

func (s staleMemoryReads) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return staleRefresh(s.MemoryStorage.GetRefreshTokenSession(ctx, signature, session))
}

type staleEntReads struct{ *EntStorage }

func (s staleEntReads) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	return staleCode(s.EntStorage.GetAuthorizeCodeSession(ctx, code, session))
}

func (s staleEntReads) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return staleRefresh(s.EntStorage.GetRefreshTokenSession(ctx, signature, session))
}

func staleCode(req fosite.Requester, err error) (fosite.Requester, error) {
	if errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) {
		return req, nil
	}
	return req, err
}

func staleRefresh(req fosite.Requester, err error) (fosite.Requester, error) {
	if errors.Is(err, fosite.ErrInactiveToken) {
		return req, nil
	}
	return req, err
}

func checkCodeExchangedOnce(t *testing.T, s *Server) {
	t.Helper()
	code := authorizeCode(t, s, "openid offline_access", headerUser(newPrincipal(t, s)))
	exchangeCode(t, s, code)

	status, body := tokenRequest(t, s, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRPCB},
		"code_verifier": {testVerifier},
	})
	if status == http.StatusOK {
		t.Fatalf("second exchange of one code succeeded: %v", body)
	}
	if _, ok := body["access_token"]; ok {
		t.Fatalf("second exchange returned an access token: %v", body)
	}
}

func checkRefreshRotatedOnce(t *testing.T, s *Server) {
	t.Helper()
	code := authorizeCode(t, s, "openid offline_access", headerUser(newPrincipal(t, s)))
	first := exchangeCode(t, s, code)
	rt1, _ := first["refresh_token"].(string)
	if rt1 == "" {
		t.Fatalf("no refresh token: %v", first)
	}

	if status, body := refresh(t, s, rt1); status != http.StatusOK {
		t.Fatalf("first refresh: %d %v", status, body)
	}
	status, body := refresh(t, s, rt1)
	if status == http.StatusOK {
		t.Fatalf("second refresh with one token succeeded: %v", body)
	}
	if _, ok := body["access_token"]; ok {
		t.Fatalf("second refresh returned an access token: %v", body)
	}
}

func newRaceEntStorage(t *testing.T) *EntStorage {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return NewEntStorage(client, WithDefaultOwner(createTestOwner(t, client)))
}

func TestCodeExchangedOnceMemory(t *testing.T) {
	checkCodeExchangedOnce(t, newRefreshTestServer(t, WithStorage(staleMemoryReads{NewMemoryStorage()})))
}

func TestCodeExchangedOnceEnt(t *testing.T) {
	checkCodeExchangedOnce(t, newRefreshTestServer(t, WithStorage(staleEntReads{newRaceEntStorage(t)})))
}

func TestRefreshRotatedOnceMemory(t *testing.T) {
	checkRefreshRotatedOnce(t, newRefreshTestServer(t, WithStorage(staleMemoryReads{NewMemoryStorage()})))
}

func TestRefreshRotatedOnceEnt(t *testing.T) {
	checkRefreshRotatedOnce(t, newRefreshTestServer(t, WithStorage(staleEntReads{newRaceEntStorage(t)})))
}

// The storage refuses directly, whatever the caller read before.
func TestInvalidateAuthorizeCodeSessionUnknownCode(t *testing.T) {
	ctx := context.Background()
	for name, s := range map[string]Storage{"memory": NewMemoryStorage(), "ent": newRaceEntStorage(t)} {
		if err := s.InvalidateAuthorizeCodeSession(ctx, "no-such-code"); !errors.Is(err, fosite.ErrNotFound) {
			t.Errorf("%s: invalidate unknown code: %v, want ErrNotFound", name, err)
		}
		if err := s.RotateRefreshToken(ctx, uuid.NewString(), "no-such-token"); !errors.Is(err, fosite.ErrInactiveToken) {
			t.Errorf("%s: rotate unknown token: %v, want ErrInactiveToken", name, err)
		}
	}
}

// A replayed code is refused and revokes the tokens issued from it.
func checkCodeReplayRevokes(t *testing.T, s *Server) {
	t.Helper()
	code := authorizeCode(t, s, "openid offline_access", headerUser(newPrincipal(t, s)))
	first := exchangeCode(t, s, code)
	at, _ := first["access_token"].(string)
	if !introspectActive(t, s, at) {
		t.Fatal("access token inactive after exchange")
	}

	status, body := tokenRequest(t, s, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRPCB},
		"code_verifier": {testVerifier},
	})
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("replayed code: %d %v, want 400 invalid_grant", status, body)
	}
	if introspectActive(t, s, at) {
		t.Error("access token from a replayed code still active")
	}
}

func TestCodeReplayRevokesMemory(t *testing.T) {
	checkCodeReplayRevokes(t, newRefreshTestServer(t))
}

func TestCodeReplayRevokesEnt(t *testing.T) {
	checkCodeReplayRevokes(t, newRefreshTestServer(t, WithStorage(newRaceEntStorage(t))))
}
