package systemauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// LoginCookieName is the SystemAuth login session cookie. The __Host-
	// prefix makes browsers enforce Secure, Path=/ and no Domain attribute,
	// so the cookie cannot be set or read by sibling subdomains.
	LoginCookieName = "__Host-sf_login"

	// loginStateCookieName binds an in-flight upstream OAuth flow to the
	// browser that started it (login-CSRF protection).
	loginStateCookieName = "__Host-sf_oauth_state"

	// insecure (development) variants without the __Host- prefix.
	insecureLoginCookieName      = "sf_login"
	insecureLoginStateCookieName = "sf_oauth_state"
)

// LoginSession is an authenticated browser session on SystemAuth.
type LoginSession struct {
	// PrincipalID is the authenticated principal.
	PrincipalID uuid.UUID

	// Provider is the upstream provider used to sign in.
	Provider string

	// CreatedAt is when the session was established.
	CreatedAt time.Time

	// ExpiresAt is the absolute session expiry.
	ExpiresAt time.Time
}

// LoginSessionStore persists login sessions keyed by an opaque session token.
// Implementations should store only a hash of the token.
type LoginSessionStore interface {
	// Create stores session under token.
	Create(ctx context.Context, token string, session LoginSession) error

	// Get returns the session for token, or ErrLoginSessionNotFound when it
	// is unknown or expired.
	Get(ctx context.Context, token string) (LoginSession, error)

	// Delete removes the session for token. Deleting an unknown token is not
	// an error.
	Delete(ctx context.Context, token string) error
}

// MemoryLoginSessionStore is an in-memory LoginSessionStore. It is suitable
// for a single SystemAuth instance; use a shared store for multiple replicas.
type MemoryLoginSessionStore struct {
	mu       sync.Mutex
	sessions map[string]LoginSession
	now      func() time.Time
}

// NewMemoryLoginSessionStore creates an empty in-memory session store.
func NewMemoryLoginSessionStore() *MemoryLoginSessionStore {
	return &MemoryLoginSessionStore{sessions: map[string]LoginSession{}, now: time.Now}
}

// Create implements LoginSessionStore. Expired sessions are pruned.
func (s *MemoryLoginSessionStore) Create(_ context.Context, token string, session LoginSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, v := range s.sessions {
		if now.After(v.ExpiresAt) {
			delete(s.sessions, k)
		}
	}
	s.sessions[hashSessionToken(token)] = session
	return nil
}

// Get implements LoginSessionStore.
func (s *MemoryLoginSessionStore) Get(_ context.Context, token string) (LoginSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashSessionToken(token)
	sess, ok := s.sessions[key]
	if !ok {
		return LoginSession{}, ErrLoginSessionNotFound
	}
	if s.now().After(sess.ExpiresAt) {
		delete(s.sessions, key)
		return LoginSession{}, ErrLoginSessionNotFound
	}
	return sess, nil
}

// Delete implements LoginSessionStore.
func (s *MemoryLoginSessionStore) Delete(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, hashSessionToken(token))
	return nil
}

var _ LoginSessionStore = (*MemoryLoginSessionStore)(nil)

func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newSessionToken returns 256 bits of randomness, URL-safe encoded.
func newSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// loginCookies writes and reads the hardened login and state cookies.
type loginCookies struct {
	sessionName string
	stateName   string
	secure      bool
}

func newLoginCookies(insecure bool) loginCookies {
	if insecure {
		return loginCookies{sessionName: insecureLoginCookieName, stateName: insecureLoginStateCookieName}
	}
	return loginCookies{sessionName: LoginCookieName, stateName: loginStateCookieName, secure: true}
}

// cookie builds a host-only, HttpOnly, Path=/ cookie. SameSite=Lax is
// required: the session must accompany the top-level navigation back from
// the upstream provider and from relying parties to /oauth/authorize.
func (c loginCookies) cookie(name, value string, maxAge int) *http.Cookie {
	//nolint:gosec // G124: HttpOnly and SameSite=Lax always; Secure unless the operator opted into InsecureCookies for local HTTP
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (c loginCookies) setSession(w http.ResponseWriter, token string, lifetime time.Duration) {
	http.SetCookie(w, c.cookie(c.sessionName, token, int(lifetime.Seconds())))
}

func (c loginCookies) setState(w http.ResponseWriter, state string, lifetime time.Duration) {
	http.SetCookie(w, c.cookie(c.stateName, state, int(lifetime.Seconds())))
}

func (c loginCookies) clearState(w http.ResponseWriter) {
	http.SetCookie(w, c.cookie(c.stateName, "", -1))
}

func cookieValue(r *http.Request, name string) string {
	ck, err := r.Cookie(name)
	if err != nil {
		// http.ErrNoCookie is the only error r.Cookie returns.
		return ""
	}
	return ck.Value
}
