package systemauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/principal"
)

// signIn completes a verified GitHub sign-in as f's current user and
// returns the session cookie.
func signIn(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	state, stateCookie := startLogin(t, s, "")
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusFound {
		t.Fatalf("sign-in: %d %s", w.Code, w.Body.String())
	}
	c := findCookie(t, w.Result(), LoginCookieName)
	if c == nil {
		t.Fatal("no session cookie")
	}
	return c
}

func requestChange(s *Server, session *http.Cookie, email string) int {
	w := postIssuerForm(s, AccountEmailPath, url.Values{"email": {email}, "csrf_token": {emailChangeCSRF(session.Value)}}, session)
	return w.Code
}

func confirmChange(s *Server, session *http.Cookie, token string) (int, string) {
	w := postIssuerForm(s, AccountEmailConfirmPath, url.Values{"token": {token}, "csrf_token": {emailChangeCSRF(session.Value)}}, session)
	return w.Code, w.Header().Get("Location")
}

func TestEmailChange(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s, sender := newMailSocialTestServer(t, f, dir, nil)
	session := signIn(t, s)
	ctx := context.Background()
	p, err := dir.FindByExternalIdentity(ctx, "github", "4242")
	if err != nil {
		t.Fatal(err)
	}

	w := getWithCookies(s, AccountEmailPath, session)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), f.email) || !strings.Contains(w.Body.String(), emailChangeCSRF(session.Value)) {
		t.Fatalf("account page: %d %s", w.Code, w.Body.String())
	}

	if code := requestChange(s, session, "new@example.com"); code != http.StatusSeeOther {
		t.Fatalf("request: %d", code)
	}
	msgs := sender.Messages()
	if len(msgs) != 2 || msgs[0].To[0].Email != "new@example.com" || msgs[1].To[0].Email != f.email {
		t.Fatalf("messages: %+v", msgs)
	}
	if !strings.Contains(msgs[1].Text, "n***@example.com") || strings.Contains(msgs[1].Text, "new@example.com") {
		t.Errorf("notice to the old address: %s", msgs[1].Text)
	}
	m := linkToken.FindStringSubmatch(msgs[0].Text)
	if m == nil || !strings.Contains(msgs[0].Text, testIssuer+AccountEmailConfirmPath) {
		t.Fatalf("no confirmation link: %s", msgs[0].Text)
	}
	token := m[1]

	// The email is unchanged until the link is used; the page shows the
	// pending change.
	if got, _ := dir.GetPrincipal(ctx, p.ID); got.Email != f.email {
		t.Fatalf("email changed before confirmation: %s", got.Email)
	}
	if w := getWithCookies(s, AccountEmailPath, session); !strings.Contains(w.Body.String(), "new@example.com") {
		t.Fatalf("pending change not shown: %s", w.Body.String())
	}
	// Opening the link shows a form and uses nothing.
	if w := getWithCookies(s, AccountEmailConfirmPath+"?token="+token, session); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), token) {
		t.Fatalf("confirm page: %d %s", w.Code, w.Body.String())
	}

	if code, loc := confirmChange(s, session, token); code != http.StatusSeeOther || loc != AccountEmailPath+"?changed=1" {
		t.Fatalf("confirm: %d %q", code, loc)
	}
	got, err := dir.GetPrincipal(ctx, p.ID)
	if err != nil || got.Email != "new@example.com" || !got.EmailVerified {
		t.Fatalf("after confirm: %+v %v", got, err)
	}
	if last := sender.Last(); last.To[0].Email != f.email || !strings.Contains(last.Subject, "was changed") {
		t.Errorf("changed notice not sent to the old address: %+v", last)
	}
	if code, _ := confirmChange(s, session, token); code != http.StatusBadRequest {
		t.Errorf("replayed link: %d, want 400", code)
	}
}

func TestEmailChangeCancel(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s, sender := newMailSocialTestServer(t, f, dir, nil)
	session := signIn(t, s)

	if code := requestChange(s, session, "new@example.com"); code != http.StatusSeeOther {
		t.Fatalf("request: %d", code)
	}
	token := linkToken.FindStringSubmatch(sender.Messages()[0].Text)[1]
	w := postIssuerForm(s, AccountEmailCancelPath, url.Values{"csrf_token": {emailChangeCSRF(session.Value)}}, session)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("cancel: %d", w.Code)
	}
	if code, _ := confirmChange(s, session, token); code != http.StatusBadRequest {
		t.Fatalf("cancelled link: %d, want 400", code)
	}
	if p, err := dir.FindByExternalIdentity(context.Background(), "github", "4242"); err != nil || p.Email != f.email {
		t.Fatalf("email after cancel: %+v %v", p, err)
	}
}

func TestEmailChangeBoundToPrincipal(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s, sender := newMailSocialTestServer(t, f, dir, nil)
	owner := signIn(t, s)
	if code := requestChange(s, owner, "new@example.com"); code != http.StatusSeeOther {
		t.Fatalf("request: %d", code)
	}
	token := linkToken.FindStringSubmatch(sender.Messages()[0].Text)[1]

	f.userID, f.email = 777, "other@example.com"
	other := signIn(t, s)
	if code, _ := confirmChange(s, other, token); code != http.StatusBadRequest {
		t.Fatalf("another account used the link: %d, want 400", code)
	}
	// Not signed in: asked to sign in, nothing used.
	if w := getWithCookies(s, AccountEmailConfirmPath+"?token="+token); w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), token) {
		t.Fatalf("confirm page signed out: %d %s", w.Code, w.Body.String())
	}
	// Form checks.
	if w := postIssuerForm(s, AccountEmailConfirmPath, url.Values{"token": {token}, "csrf_token": {"forged"}}, owner); w.Code != http.StatusForbidden {
		t.Fatalf("forged CSRF token: %d, want 403", w.Code)
	}
	if code, _ := confirmChange(s, owner, token); code != http.StatusSeeOther {
		t.Fatalf("owner's confirm after failed attempts: %d", code)
	}
}

func TestEmailChangeDoesNotRevealAccounts(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	if err := dir.AddPrincipal(HumanPrincipal{Email: "taken@example.com", EmailVerified: true, Active: true}); err != nil {
		t.Fatal(err)
	}
	s, sender := newMailSocialTestServer(t, f, dir, nil)
	session := signIn(t, s)

	// Requesting an address another account has looks like any request.
	if code := requestChange(s, session, "taken@example.com"); code != http.StatusSeeOther {
		t.Fatalf("request for a taken address: %d, want 303", code)
	}
	if sender.Len() != 2 {
		t.Fatalf("messages = %d, want the link and the notice", sender.Len())
	}
	// Only the mailbox's owner learns, on confirming, that it cannot be used.
	token := linkToken.FindStringSubmatch(sender.Messages()[0].Text)[1]
	w := postIssuerForm(s, AccountEmailConfirmPath, url.Values{"token": {token}, "csrf_token": {emailChangeCSRF(session.Value)}}, session)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "cannot be used") {
		t.Fatalf("confirm a taken address: %d %s", w.Code, w.Body.String())
	}
	if p, err := dir.FindByExternalIdentity(context.Background(), "github", "4242"); err != nil || p.Email != f.email {
		t.Fatalf("email after conflict: %+v %v", p, err)
	}

	// Invalid and unchanged addresses are refused before anything is sent.
	for _, bad := range []string{"not an address", "Name <x@example.com>", f.email, strings.ToUpper(f.email)} {
		if code := requestChange(s, session, bad); code != http.StatusBadRequest {
			t.Errorf("request %q: %d, want 400", bad, code)
		}
	}
	if sender.Len() != 2 {
		t.Fatalf("refused requests sent mail: %d messages", sender.Len())
	}
}

func TestEmailChangeStale(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s, sender := newMailSocialTestServer(t, f, dir, nil)
	session := signIn(t, s)
	p, err := dir.FindByExternalIdentity(context.Background(), "github", "4242")
	if err != nil {
		t.Fatal(err)
	}
	if code := requestChange(s, session, "new@example.com"); code != http.StatusSeeOther {
		t.Fatalf("request: %d", code)
	}
	token := linkToken.FindStringSubmatch(sender.Messages()[0].Text)[1]
	if err := dir.ChangeEmail(context.Background(), p.ID, f.email, "elsewhere@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	if code, _ := confirmChange(s, session, token); code != http.StatusBadRequest {
		t.Fatalf("stale change: %d, want 400", code)
	}
	if got, _ := dir.GetPrincipal(context.Background(), p.ID); got.Email != "elsewhere@example.com" {
		t.Fatalf("stale change applied: %s", got.Email)
	}
}

func TestEmailChangeNeedsSignIn(t *testing.T) {
	s, _ := newMailSocialTestServer(t, newFakeGitHub(t), NewMemoryPrincipalDirectory(), nil)
	w := getWithCookies(s, AccountEmailPath)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), url.QueryEscape(AccountEmailPath)) {
		t.Fatalf("signed out: %d %s", w.Code, w.Body.String())
	}
	// Without mail the routes are not mounted.
	plain := newSocialTestServer(t, newFakeGitHub(t), NewMemoryPrincipalDirectory())
	if w := getWithCookies(plain, AccountEmailPath); w.Code != http.StatusNotFound {
		t.Fatalf("without mail: %d, want 404", w.Code)
	}
}

func TestEntChangeEmail(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	dir := NewEntPrincipalDirectory(db)
	id := seedHuman(t, db, "old@example.com", false)
	seedHuman(t, db, "taken@example.com", true)

	if err := dir.ChangeEmail(ctx, id, "old@example.com", "Taken@example.com", time.Now()); !errors.Is(err, ErrEmailConflict) {
		t.Fatalf("taken address: %v, want ErrEmailConflict", err)
	}
	if err := dir.ChangeEmail(ctx, id, "someone@example.com", "new@example.com", time.Now()); !errors.Is(err, ErrEmailChangeStale) {
		t.Fatalf("stale: %v, want ErrEmailChangeStale", err)
	}
	at := time.Now().Truncate(time.Second)
	if err := dir.ChangeEmail(ctx, id, "OLD@example.com", "new@example.com", at); err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}
	h, err := db.Human.Query().Where(human.PrincipalIDEQ(id)).Only(ctx)
	if err != nil || h.Email == nil || *h.Email != "new@example.com" || h.EmailVerifiedAt == nil || !h.EmailVerifiedAt.Equal(at) {
		t.Fatalf("human after change: %+v %v", h, err)
	}
	if p, err := db.Principal.Query().Where(principal.IDEQ(id)).Only(ctx); err != nil || p.Identifier != "new@example.com" {
		t.Fatalf("principal identifier: %+v %v", p, err)
	}
	if _, err := dir.FindByVerifiedEmail(ctx, "new@example.com"); err != nil {
		t.Fatalf("new address not verified: %v", err)
	}
}
