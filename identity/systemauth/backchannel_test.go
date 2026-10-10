package systemauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/accesschange"
)

func TestValidateBackchannelLogoutURI(t *testing.T) {
	for uri, ok := range map[string]bool{
		"":                                 true,
		"https://app.example.com/bc":       true,
		"http://localhost:8080/bc":         true,
		"http://127.0.0.1/bc":              true,
		"http://app.example.com/bc":        false,
		"ftp://app.example.com/bc":         false,
		"/relative":                        false,
		"https://user:pw@app.example.com/": false,
		"https://app.example.com/#frag":    false,
		"https://":                         false,
	} {
		err := ValidateBackchannelLogoutURI(uri)
		if ok && err != nil {
			t.Errorf("%q refused: %v", uri, err)
		}
		if !ok && !errors.Is(err, ErrInvalidBackchannelURI) {
			t.Errorf("%q = %v, want ErrInvalidBackchannelURI", uri, err)
		}
	}
	if _, err := NewClientFromConfig(ClientConfig{ID: "x", Name: "X", Type: "public", BackchannelLogoutURI: "http://evil.example.com/"}); !errors.Is(err, ErrInvalidBackchannelURI) {
		t.Errorf("NewClientFromConfig accepted a plain-http endpoint: %v", err)
	}
}

// receiver is a back-channel endpoint that records what it is sent.
type receiver struct {
	mu     sync.Mutex
	tokens []string
	status []int // responses to give in turn; the last repeats
	hits   int
	srv    *httptest.Server
}

func newReceiver(t *testing.T, status ...int) *receiver {
	t.Helper()
	r := &receiver{status: status}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			t.Errorf("form: %v", err)
		}
		r.mu.Lock()
		r.hits++
		r.tokens = append(r.tokens, req.PostForm.Get("logout_token"))
		code := r.status[min(r.hits-1, len(r.status)-1)]
		r.mu.Unlock()
		if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("request: %s %q", req.Method, req.Header.Get("Content-Type"))
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits
}

func (r *receiver) waitFor(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for r.count() < n {
		select {
		case <-deadline:
			t.Fatalf("receiver saw %d requests, want %d", r.count(), n)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func backchannelServer(t *testing.T, clients ...ClientConfig) (*Server, *Backchannel) {
	t.Helper()
	s, err := NewEmbedded(Config{Issuer: testIssuer, Clients: clients})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s, s.NewBackchannel(WithBackchannelBackoff(5*time.Millisecond, 20*time.Millisecond))
}

func runBackchannel(t *testing.T, b *Backchannel) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = b.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// verify parses a delivered token against the server's key.
func verifyLogoutToken(t *testing.T, s *Server, raw string) gojwt.MapClaims {
	t.Helper()
	claims := gojwt.MapClaims{}
	tok, err := gojwt.ParseWithClaims(raw, claims, func(*gojwt.Token) (any, error) { return &s.key.PublicKey, nil },
		gojwt.WithValidMethods([]string{"RS256"}), gojwt.WithIssuer(testIssuer))
	if err != nil {
		t.Fatalf("delivered token does not verify: %v", err)
	}
	if tok.Header["typ"] != LogoutTokenType || tok.Header["kid"] != s.KeyID() {
		t.Errorf("header = %v", tok.Header)
	}
	return claims
}

func TestBackchannelDeliversAccessChanges(t *testing.T) {
	rcv := newReceiver(t, http.StatusOK)
	s, b := backchannelServer(t,
		ClientConfig{ID: "rp", Type: "public", Name: "RP", BackchannelLogoutURI: rcv.srv.URL},
		ClientConfig{ID: "quiet", Type: "public", Name: "Quiet"},
	)
	runBackchannel(t, b)

	p, org := uuid.New(), uuid.New()
	b.AccessChange(accesschange.Change{PrincipalID: p, OrganizationID: &org, ChangedAt: time.Now(), Reason: accesschange.MembershipRemoved})
	rcv.waitFor(t, 1)
	claims := verifyLogoutToken(t, s, rcv.tokens[0])
	if claims["sub"] != p.String() || claims["aud"] != "rp" || claims["jti"] == "" || claims["nonce"] != nil {
		t.Errorf("claims = %v", claims)
	}
	events, _ := claims["events"].(map[string]any)
	ev, _ := events[EventAccessChange].(map[string]any)
	if ev["organization_id"] != org.String() || ev["reason"] != "membership_removed" || ev["changed_at"] == "" {
		t.Errorf("access_change event = %v", events)
	}
	if _, logout := events[EventBackchannelLogout]; logout {
		t.Error("a membership removal also logged the person out")
	}

	// A deactivation also ends sessions, and is not scoped to an organization.
	b.AccessChange(accesschange.Change{PrincipalID: p, ChangedAt: time.Now(), Reason: accesschange.Deactivated})
	rcv.waitFor(t, 2)
	events, _ = verifyLogoutToken(t, s, rcv.tokens[1])["events"].(map[string]any)
	ev, _ = events[EventAccessChange].(map[string]any)
	if _, logout := events[EventBackchannelLogout]; !logout || ev["organization_id"] != nil {
		t.Errorf("deactivation events = %v", events)
	}
	// Each delivery has its own jti.
	if verifyLogoutToken(t, s, rcv.tokens[0])["jti"] == verifyLogoutToken(t, s, rcv.tokens[1])["jti"] {
		t.Error("two tokens share a jti")
	}
}

func TestBackchannelRetriesTransientFailures(t *testing.T) {
	rcv := newReceiver(t, http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusOK)
	_, b := backchannelServer(t, ClientConfig{ID: "rp", Type: "public", Name: "RP", BackchannelLogoutURI: rcv.srv.URL})
	runBackchannel(t, b)
	b.AccessChange(accesschange.Change{PrincipalID: uuid.New(), ChangedAt: time.Now(), Reason: accesschange.SessionsRevoked})
	rcv.waitFor(t, 3)
	time.Sleep(100 * time.Millisecond)
	if n := rcv.count(); n != 3 {
		t.Errorf("%d requests; a delivered change must not be sent again", n)
	}
}

func TestBackchannelDoesNotRetryRefusals(t *testing.T) {
	rcv := newReceiver(t, http.StatusBadRequest)
	_, b := backchannelServer(t, ClientConfig{ID: "rp", Type: "public", Name: "RP", BackchannelLogoutURI: rcv.srv.URL})
	runBackchannel(t, b)
	b.AccessChange(accesschange.Change{PrincipalID: uuid.New(), ChangedAt: time.Now(), Reason: accesschange.Deactivated})
	rcv.waitFor(t, 1)
	time.Sleep(150 * time.Millisecond)
	if n := rcv.count(); n != 1 {
		t.Errorf("a 400 was retried: %d requests", n)
	}
}

func TestBackchannelAbandonsAfterOneTokenLifetime(t *testing.T) {
	rcv := newReceiver(t, http.StatusServiceUnavailable)
	_, b := backchannelServer(t, ClientConfig{ID: "rp", Type: "public", Name: "RP", BackchannelLogoutURI: rcv.srv.URL})
	runBackchannel(t, b)
	// A change from 20 minutes ago is past the point where any token issued
	// before it can still be valid: one attempt, no retry.
	b.AccessChange(accesschange.Change{PrincipalID: uuid.New(), ChangedAt: time.Now().Add(-20 * time.Minute), Reason: accesschange.Deactivated})
	rcv.waitFor(t, 1)
	time.Sleep(150 * time.Millisecond)
	if n := rcv.count(); n != 1 {
		t.Errorf("%d requests for a change past its deadline, want 1", n)
	}
}

func TestBackchannelDoesNotFollowRedirects(t *testing.T) {
	target := newReceiver(t, http.StatusOK)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.srv.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)
	_, b := backchannelServer(t, ClientConfig{ID: "rp", Type: "public", Name: "RP", BackchannelLogoutURI: redirector.URL})
	runBackchannel(t, b)
	b.AccessChange(accesschange.Change{PrincipalID: uuid.New(), ChangedAt: time.Now(), Reason: accesschange.Deactivated})
	time.Sleep(200 * time.Millisecond)
	if n := target.count(); n != 0 {
		t.Errorf("a redirect was followed: %d requests reached the target", n)
	}
}

func TestBackchannelClientURIRoundTripsThroughEntStorage(t *testing.T) {
	db := openTestEnt(t)
	st := NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))
	ctx := t.Context()
	c, err := NewClientFromConfig(ClientConfig{ID: "rp", Type: "public", Name: "RP", BackchannelLogoutURI: "https://rp.example.com/bc"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetClientByID(ctx, "rp")
	if err != nil || got.BackchannelLogoutURI != "https://rp.example.com/bc" {
		t.Fatalf("stored client = %+v, %v", got, err)
	}
	got.BackchannelLogoutURI = ""
	if err := st.UpdateClient(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, err := st.GetClientByID(ctx, "rp"); err != nil || again.BackchannelLogoutURI != "" {
		t.Errorf("cleared client = %+v, %v", again, err)
	}
}
