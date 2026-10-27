// Package publicclient lets a public client, such as a command-line tool, sign
// a person in to SystemAuth and call SystemForge-powered APIs with
// DPoP-bound access tokens (RFC 9449).
//
// A public client cannot keep a secret, so it signs in with the
// authorization code flow and PKCE on a loopback redirect (RFC 8252) and
// proves possession of a key instead. Nothing is registered ahead of time:
// [Login] generates a P-256 key, SystemAuth binds the tokens it issues to
// the key's thumbprint (cnf.jkt), and every API request a [Session] sends
// carries a fresh proof by the key, bound to the access token. The key
// matters only while tokens bound to it live; logging in again makes a new
// one.
//
// The client must be registered at SystemAuth as a public client with the
// redirect URI http://127.0.0.1/callback, which SystemAuth matches on any
// port as RFC 8252 requires, and the authorization_code and refresh_token
// grants. An application marked first_party skips the consent screen,
// which suits a tool shipped to the deployment's own users; any other
// client asks the person to consent. Never grant a distributed client
// SystemAuth's allow_bearer_tokens exception: the binding is what makes a
// leaked token useless.
package publicclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/grokify/goauth/dpop"
	"golang.org/x/oauth2"

	"github.com/plexusone/systemforge/identity/relyingparty"
)

// CallbackPath is the path of the loopback redirect URI.
const CallbackPath = "/callback"

// RegisteredRedirectURI is the redirect URI to register for the client at
// SystemAuth; the login listens on a free port, which SystemAuth accepts
// for a loopback URI.
const RegisteredRedirectURI = "http://127.0.0.1" + CallbackPath

// refreshSkew is how long before expiry an access token is refreshed.
const refreshSkew = time.Minute

// Config configures a public client.
type Config struct {
	// Issuer is the SystemAuth issuer URL. Required.
	Issuer string
	// ClientID is the client's OAuth client ID at SystemAuth. Required.
	ClientID string
	// Scopes requested at login. Default: relyingparty.DefaultScopes,
	// which include offline_access for a refresh token.
	Scopes []string
	// Store keeps the key and the tokens between runs. Required.
	Store Store
	// HTTPClient makes the requests to SystemAuth, and is the base of
	// [Session.HTTPClient]. Default: http.DefaultClient.
	HTTPClient *http.Client
	// Metadata is SystemAuth's provider metadata, when already known; nil
	// discovers it from Issuer.
	Metadata *relyingparty.Metadata
	// CallbackPort is the loopback port Login listens on. Default: a free
	// port.
	CallbackPort int
}

func (c Config) validate() error {
	switch {
	case c.Issuer == "":
		return errors.New("publicclient: Config.Issuer is required")
	case c.ClientID == "":
		return errors.New("publicclient: Config.ClientID is required")
	case c.Store == nil:
		return errors.New("publicclient: Config.Store is required")
	}
	return nil
}

func (c Config) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

// rpClient returns the relying-party client that signs the token requests
// with key. redirect matters only for the login's code exchange.
func (c Config) rpClient(ctx context.Context, redirect string, key *dpop.KeyPair) (*relyingparty.Client, error) {
	rc := relyingparty.Config{
		Issuer:      c.Issuer,
		ClientID:    c.ClientID,
		RedirectURL: redirect,
		Scopes:      c.Scopes,
		HTTPClient:  c.httpClient(),
		DPoPKey:     key,
	}
	if c.Metadata != nil {
		return relyingparty.NewClientWithMetadata(rc, *c.Metadata)
	}
	return relyingparty.NewClient(ctx, rc)
}

// Identity is the person a session acts for.
type Identity struct {
	Subject string
	Email   string
}

// Session holds a signed-in person's DPoP key and tokens. It is safe for
// concurrent use.
type Session struct {
	cfg    Config
	client *relyingparty.Client
	key    *dpop.KeyPair

	mu    sync.Mutex
	creds Credentials
	// nonces are the latest DPoP nonces servers handed out, by origin.
	nonces map[string]string
}

// Login signs a person in: it listens on a loopback port, calls open with
// the authorization URL (to open a browser, or print it for the person),
// waits for SystemAuth's redirect, exchanges the code for tokens bound to a
// new DPoP key, verifies the ID token, and saves the key and tokens in
// cfg.Store, replacing what was there.
func Login(ctx context.Context, cfg Config, open func(authURL string) error) (s *Session, err error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if open == nil {
		return nil, errors.New("publicclient: Login needs a function that opens the authorization URL")
	}
	key, err := dpop.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("publicclient: generating a DPoP key: %w", err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.CallbackPort)))
	if err != nil {
		return nil, fmt.Errorf("publicclient: listening for the login redirect: %w", err)
	}
	redirect := "http://" + ln.Addr().String() + CallbackPath
	client, err := cfg.rpClient(ctx, redirect, key)
	if err != nil {
		return nil, errors.Join(err, ln.Close())
	}
	state, err := randomString()
	if err != nil {
		return nil, errors.Join(err, ln.Close())
	}
	nonce, err := randomString()
	if err != nil {
		return nil, errors.Join(err, ln.Close())
	}
	verifier := oauth2.GenerateVerifier()

	codes := make(chan callbackResult, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: callbackHandler(state, codes)}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	defer func() {
		if cerr := srv.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("publicclient: closing the login listener: %w", cerr))
		}
		if serr := <-served; serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			err = errors.Join(err, fmt.Errorf("publicclient: login listener: %w", serr))
		}
	}()

	if err := open(client.AuthCodeURL(state, nonce, verifier)); err != nil {
		return nil, fmt.Errorf("publicclient: opening the authorization URL: %w", err)
	}
	var code string
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("publicclient: waiting for the login: %w", ctx.Err())
	case r := <-codes:
		if r.err != nil {
			return nil, r.err
		}
		code = r.code
	}

	tok, err := client.Exchange(ctx, code, verifier)
	if err != nil {
		return nil, fmt.Errorf("publicclient: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, errors.New("publicclient: SystemAuth returned no ID token")
	}
	idt, err := client.VerifyIDToken(ctx, rawID, nonce)
	if err != nil {
		return nil, fmt.Errorf("publicclient: %w", err)
	}
	serialized, err := key.SerializeJSON()
	if err != nil {
		return nil, fmt.Errorf("publicclient: serializing the DPoP key: %w", err)
	}
	creds := Credentials{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID, DPoPKey: serialized,
		AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, Expiry: tok.Expiry,
		Subject: idt.Subject, Email: idt.Email,
	}
	if err := cfg.Store.Save(ctx, &creds); err != nil {
		return nil, err
	}
	return &Session{cfg: cfg, client: client, key: key, creds: creds, nonces: map[string]string{}}, nil
}

type callbackResult struct {
	code string
	err  error
}

// callbackHandler receives SystemAuth's redirect, checks state, and sends
// the code (or the error SystemAuth reported) on codes once.
func callbackHandler(state string, codes chan<- callbackResult) http.Handler {
	var once sync.Once
	finish := func(r callbackResult) { once.Do(func() { codes <- r }) }
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != CallbackPath {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		var res callbackResult
		switch {
		case q.Get("state") != state:
			// Not this login's redirect; keep waiting for it.
			http.Error(w, "This sign-in link does not belong to the login in progress.", http.StatusBadRequest)
			return
		case q.Get("error") != "":
			res.err = fmt.Errorf("publicclient: SystemAuth refused the login: %s %s", q.Get("error"), q.Get("error_description"))
		case q.Get("code") == "":
			res.err = errors.New("publicclient: SystemAuth's redirect carried no code")
		default:
			res.code = q.Get("code")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		msg := "Signed in. You can close this tab and return to the terminal."
		if res.err != nil {
			w.WriteHeader(http.StatusBadRequest)
			msg = "Sign-in failed: " + res.err.Error()
		}
		if _, err := fmt.Fprintf(w, "<!doctype html><title>Sign-in</title><p>%s</p>", html.EscapeString(msg)); err != nil {
			res.err = errors.Join(res.err, fmt.Errorf("publicclient: answering the login redirect: %w", err))
		}
		finish(res)
	})
}

func randomString() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("publicclient: random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Open returns the session stored in cfg.Store, or ErrNotLoggedIn. It
// refuses credentials of another issuer or client.
func Open(ctx context.Context, cfg Config) (*Session, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	creds, err := cfg.Store.Load(ctx)
	if err != nil {
		return nil, err
	}
	if creds.Issuer != cfg.Issuer || creds.ClientID != cfg.ClientID {
		return nil, fmt.Errorf("%w: the stored credentials are for client %q at %s", ErrNotLoggedIn, creds.ClientID, creds.Issuer)
	}
	key, err := dpop.DeserializeKeyPairJSON(creds.DPoPKey)
	if err != nil {
		return nil, fmt.Errorf("publicclient: stored DPoP key: %w", err)
	}
	client, err := cfg.rpClient(ctx, RegisteredRedirectURI, key)
	if err != nil {
		return nil, err
	}
	return &Session{cfg: cfg, client: client, key: key, creds: *creds, nonces: map[string]string{}}, nil
}

// Identity returns the person the session acts for.
func (s *Session) Identity() Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Identity{Subject: s.creds.Subject, Email: s.creds.Email}
}

// DPoPThumbprint returns the thumbprint of the key the session's tokens
// are bound to.
func (s *Session) DPoPThumbprint() string { return s.key.Thumbprint }

// AccessToken returns an access token valid for at least a minute,
// refreshing it first when needed. Present it only with a DPoP proof by
// the session's key, as the Transport does.
func (s *Session) AccessToken(ctx context.Context) (string, error) {
	return s.token(ctx, "")
}

// token returns a usable access token. stale, when set, is a token a
// server just refused: it is refreshed even if it has not expired.
func (s *Session) token(ctx context.Context, stale string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.usable(stale) {
		return s.creds.AccessToken, nil
	}
	if s.creds.RefreshToken == "" {
		return "", fmt.Errorf("%w: the access token expired and there is no refresh token", ErrNotLoggedIn)
	}
	return s.refreshLocked(ctx, stale)
}

// usable reports whether the session's access token can be sent.
func (s *Session) usable(stale string) bool {
	return s.creds.AccessToken != "" && s.creds.AccessToken != stale &&
		(s.creds.Expiry.IsZero() || time.Until(s.creds.Expiry) > refreshSkew)
}

// refreshLocked refreshes the tokens under the store's lock (s.mu held).
// Another process may have refreshed meanwhile: its tokens are adopted
// instead of redeeming a refresh token that was already used.
func (s *Session) refreshLocked(ctx context.Context, stale string) (tok string, err error) {
	if l, ok := s.cfg.Store.(Locker); ok {
		unlock, err := l.Lock(ctx)
		if err != nil {
			return "", err
		}
		defer func() {
			if uerr := unlock(); uerr != nil {
				err = errors.Join(err, uerr)
			}
		}()
	}
	stored, err := s.cfg.Store.Load(ctx)
	if err != nil {
		return "", err // ErrNotLoggedIn: another process logged out
	}
	if stored.RefreshToken != s.creds.RefreshToken && slices.Equal(stored.DPoPKey, s.creds.DPoPKey) {
		s.creds = *stored
		if s.usable(stale) {
			return s.creds.AccessToken, nil
		}
	}
	next, err := s.client.Refresh(ctx, s.creds.RefreshToken)
	if err != nil {
		return "", fmt.Errorf("publicclient: %w", err)
	}
	s.creds.AccessToken, s.creds.Expiry = next.AccessToken, next.Expiry
	if next.RefreshToken != "" {
		s.creds.RefreshToken = next.RefreshToken
	}
	if err := s.cfg.Store.Save(ctx, &s.creds); err != nil {
		return "", err
	}
	return s.creds.AccessToken, nil
}

// Logout revokes the refresh token at SystemAuth, which revokes its token
// family, and deletes the stored credentials. The credentials are deleted
// even when the revocation fails; its error is returned.
func (s *Session) Logout(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	if s.creds.RefreshToken != "" {
		if err := s.client.Revoke(ctx, s.creds.RefreshToken, "refresh_token"); err != nil {
			errs = append(errs, fmt.Errorf("publicclient: revoking the refresh token: %w", err))
		}
	}
	if err := s.cfg.Store.Delete(ctx); err != nil {
		errs = append(errs, err)
	}
	s.creds = Credentials{}
	return errors.Join(errs...)
}
