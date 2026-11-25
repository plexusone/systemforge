package relyingparty_test

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/grokify/goauth/dpop"
	"github.com/plexusone/omnimail/memsender"

	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/systemauth"
)

var signInCode = regexp.MustCompile(`(?m)^(\d{6})$`)

// TestEmailSignInThroughRelyingParty signs a person in with a mailed code
// through a real SystemAuth and a real relying party, with a browser that
// follows redirects and keeps cookies: the app's "continue with email" link,
// SystemAuth's address and code pages, the authorization code, the app's
// callback and its session.
func TestEmailSignInThroughRelyingParty(t *testing.T) {
	var (
		sa  *systemauth.Server
		bff *relyingparty.BFF
	)
	saSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sa.ServeHTTP(w, r) }))
	t.Cleanup(saSrv.Close)
	appSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { bff.ServeHTTP(w, r) }))
	t.Cleanup(appSrv.Close)

	callback := appSrv.URL + "/bff/auth/callback"
	mail := memsender.New()
	// One store holds the accounts sign-in creates and the ones the token
	// endpoint checks, as the database does in a deployment.
	storage := systemauth.NewMemoryStorage()
	var err error
	sa, err = systemauth.NewEmbedded(systemauth.Config{
		Issuer: saSrv.URL,
		Clients: []systemauth.ClientConfig{{
			ID: "app", Type: "public", Name: "App",
			RedirectURIs:  []string{callback},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
		Features: systemauth.FeatureConfig{RequirePKCE: true, EnableJWTAccessTokens: true},
		SocialLogin: &systemauth.SocialLoginConfig{
			AllowedRedirectOrigins: []string{saSrv.URL},
			InsecureCookies:        true, // plain HTTP in the test
			Email:                  &systemauth.EmailLoginConfig{},
		},
		Mail: &systemauth.MailConfig{Provider: systemauth.MailProviderSES, From: "Example <no-reply@example.com>", ProductName: "Example"},
	}, systemauth.WithStorage(storage), systemauth.WithMailSender(mail), systemauth.WithPrincipalDirectory(storage.PrincipalDirectory()))
	if err != nil {
		t.Fatalf("systemauth: %v", err)
	}

	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	client, err := relyingparty.NewClient(t.Context(), relyingparty.Config{Issuer: saSrv.URL, ClientID: "app", RedirectURL: callback, DPoPKey: kp})
	if err != nil {
		t.Fatalf("relying party client: %v", err)
	}
	store := relyingparty.NewMemoryPrincipalStore()
	bff, err = relyingparty.NewBFF(relyingparty.BFFConfig{Client: client, Principals: store, InsecureCookies: true})
	if err != nil {
		t.Fatalf("BFF: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar}

	body := func(resp *http.Response) string {
		t.Helper()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("closing body: %v", err)
			}
		}()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	get := func(target string) *http.Response {
		t.Helper()
		resp, err := browser.Get(target) //nolint:noctx // a test browser
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		return resp
	}
	post := func(target string, form url.Values) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", saSrv.URL)
		resp, err := browser.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", target, err)
		}
		return resp
	}
	hidden := func(page, name string) string {
		t.Helper()
		m := regexp.MustCompile(`name="` + name + `" value="([^"]*)"`).FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("no %s field in %s", name, page)
		}
		return html.UnescapeString(m[1])
	}

	// 1. The app's "continue with email" link goes through the BFF to
	// SystemAuth with the hint, and SystemAuth shows its address form.
	resp := get(appSrv.URL + "/bff/auth/email?return_to=%2Fhome")
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != systemauth.EmailLoginPath {
		t.Fatalf("after the email link: %d at %s", resp.StatusCode, resp.Request.URL)
	}
	page := body(resp)
	if !strings.Contains(page, `name="email"`) {
		t.Fatalf("no address form: %s", page)
	}
	returnTo := hidden(page, "return_to")
	if !strings.Contains(returnTo, "idp_hint=email") || !strings.Contains(returnTo, "/oauth/authorize") {
		t.Fatalf("the form does not resume the authorization request with the hint: %s", returnTo)
	}

	// 2. The person asks for a code, gets it by mail and enters it.
	resp = post(saSrv.URL+systemauth.EmailLoginPath, url.Values{"email": {"dev@example.com"}, "return_to": {returnTo}})
	page = body(resp)
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != systemauth.EmailCodePath {
		t.Fatalf("after asking for a code: %d at %s: %s", resp.StatusCode, resp.Request.URL, page)
	}
	msg := mail.Last()
	if msg == nil || mail.Len() != 1 || msg.To[0].Email != "dev@example.com" {
		t.Fatalf("mail: %d messages, last %+v", mail.Len(), msg)
	}
	m := signInCode.FindStringSubmatch(msg.Text)
	if m == nil {
		t.Fatalf("no code in the message: %s", msg.Text)
	}
	if c := mail.Last().Text; strings.Contains(page, m[1]) || strings.Contains(c, "token=") {
		t.Fatal("the code leaked into the page, or the message carries a link")
	}

	resp = post(saSrv.URL+systemauth.EmailCodePath, url.Values{"code": {m[1]}, "csrf_token": {hidden(page, "csrf_token")}})
	final := resp.Request.URL
	finalBody := body(resp)

	// 3. The sign-in resumed the authorization request, SystemAuth sent the
	// browser to the app's callback, and the app made its session and sent
	// the person where they were going (the app serves no /home page here, so
	// the page itself is a 404).
	if want := strings.TrimPrefix(appSrv.URL, "http://"); final.Host != want || final.Path != "/home" {
		t.Fatalf("ended at %s (%d), want the app's /home: %s", final, resp.StatusCode, finalBody)
	}
	resp = get(appSrv.URL + "/bff/api/v1/users/me")
	var me struct {
		Email string `json:"email"`
		ID    string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body(resp)), &me); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("the app's session: %d %v", resp.StatusCode, err)
	}
	if me.Email != "dev@example.com" || me.ID == "" {
		t.Fatalf("the app signed in %+v, want dev@example.com", me)
	}
	p, err := store.FindByEmail(t.Context(), "dev@example.com")
	if err != nil || p.Email != "dev@example.com" {
		t.Fatalf("the app's principal: %+v %v", p, err)
	}

	// 4. A second sign-in by the same address reaches the same account.
	jar2, _ := cookiejar.New(nil)
	browser.Jar = jar2
	resp = get(appSrv.URL + "/bff/auth/email?return_to=%2Fhome")
	page = body(resp)
	resp = post(saSrv.URL+systemauth.EmailLoginPath, url.Values{"email": {"dev@example.com"}, "return_to": {hidden(page, "return_to")}})
	page = body(resp)
	code := signInCode.FindStringSubmatch(mail.Last().Text)[1]
	resp = post(saSrv.URL+systemauth.EmailCodePath, url.Values{"code": {code}, "csrf_token": {hidden(page, "csrf_token")}})
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	resp = get(appSrv.URL + "/bff/api/v1/users/me")
	var again struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body(resp)), &again); err != nil || again.ID != me.ID {
		t.Fatalf("the second sign-in reached %q (%v), want the same account %q", again.ID, err, me.ID)
	}
}
