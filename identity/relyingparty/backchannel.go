package relyingparty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// Event identifiers in a logout token's "events" claim.
const (
	// EventBackchannelLogout is the OpenID Connect Back-Channel Logout 1.0
	// event: end the sessions of the token's sub (or sid).
	EventBackchannelLogout = "http://schemas.openid.net/event/backchannel-logout"
	// EventAccessChange announces a reduction of the sub's access
	// (ADR-010).
	EventAccessChange = "urn:systemforge:event:access_change"
)

// LogoutTokenType is the JOSE typ header of a logout token.
const LogoutTokenType = "logout+jwt" //nolint:gosec // G101: a JOSE typ value, not a credential

// LogoutTokenClaims are the verified claims of a SystemAuth logout token.
type LogoutTokenClaims struct {
	gojwt.RegisteredClaims

	SID    string                     `json:"sid,omitempty"`
	Nonce  string                     `json:"nonce,omitempty"`
	Events map[string]json.RawMessage `json:"events"`
}

// LogoutTokenVerifier verifies logout tokens. *Client implements it.
type LogoutTokenVerifier interface {
	VerifyLogoutToken(ctx context.Context, raw string) (*LogoutTokenClaims, error)
}

// VerifyLogoutToken verifies a logout token per OpenID Connect Back-Channel
// Logout 1.0 section 2.6: RS256 signature against the SystemAuth JWKS, iss
// equal to the issuer, aud containing the client ID, a jti, an expiry,
// typ logout+jwt, no nonce, an events claim naming the back-channel logout
// or access-change event, and a sub or sid.
func (c *Client) VerifyLogoutToken(ctx context.Context, raw string) (*LogoutTokenClaims, error) {
	header := gojwt.MapClaims{}
	tok, _, err := gojwt.NewParser().ParseUnverified(raw, header)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	// An ID token or access token must not pass as a logout token.
	if typ, _ := tok.Header["typ"].(string); typ != LogoutTokenType {
		return nil, fmt.Errorf("%w: typ %q is not %s", ErrInvalidToken, typ, LogoutTokenType)
	}
	claims := &LogoutTokenClaims{}
	if err := c.keys.Verify(ctx, raw, c.cfg.Issuer, claims); err != nil {
		return nil, err
	}
	if !slices.Contains(claims.Audience, c.cfg.ClientID) {
		return nil, fmt.Errorf("%w: audience %v does not include %q", ErrInvalidToken, claims.Audience, c.cfg.ClientID)
	}
	switch {
	case claims.ID == "":
		return nil, fmt.Errorf("%w: missing jti", ErrInvalidToken)
	case claims.Nonce != "":
		return nil, fmt.Errorf("%w: a logout token has no nonce", ErrInvalidToken)
	case claims.Subject == "" && claims.SID == "":
		return nil, fmt.Errorf("%w: missing sub and sid", ErrInvalidToken)
	}
	_, logout := claims.Events[EventBackchannelLogout]
	_, change := claims.Events[EventAccessChange]
	if !logout && !change {
		return nil, fmt.Errorf("%w: no recognized event", ErrInvalidToken)
	}
	return claims, nil
}

// BackchannelOption configures BackchannelHandler.
type BackchannelOption func(*backchannelHandler)

// WithBackchannelSessions deletes the sessions of a logout event's sub or
// sid from store, as the OIDC logout requires of a relying party with
// server-side sessions.
func WithBackchannelSessions(store SessionStore) BackchannelOption {
	return func(h *backchannelHandler) { h.sessions = store }
}

// WithBackchannelLogger sets the logger for refused tokens and failures.
func WithBackchannelLogger(l *slog.Logger) BackchannelOption {
	return func(h *backchannelHandler) { h.logger = l }
}

type backchannelHandler struct {
	sink     AccessChangeSink
	verifier LogoutTokenVerifier
	sessions SessionStore
	logger   *slog.Logger
	now      func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time // jti -> expiry, to refuse a replayed token
}

// BackchannelHandler returns the endpoint SystemAuth POSTs logout tokens to
// (ADR-010 decision 4, separate deployments; register its URL as the
// client's backchannel_logout_uri). It verifies the token with verifier and
// then
//
//   - records an access_change event into sink (a RevocationCache), so
//     tokens issued before the change are refused;
//   - on a back-channel logout event, deletes the sessions of the token's
//     sid, or of its sub, when WithBackchannelSessions gave it a store.
//
// It answers 200 on success, 400 for a token that fails verification or a
// replayed jti, and 500 when sessions cannot be deleted, which makes
// SystemAuth retry. sink may be nil to handle logout events only.
func BackchannelHandler(sink AccessChangeSink, verifier LogoutTokenVerifier, opts ...BackchannelOption) http.Handler {
	h := &backchannelHandler{sink: sink, verifier: verifier, logger: slog.Default(), now: time.Now, seen: map[string]time.Time{}}
	for _, o := range opts {
		o(h)
	}
	return h
}

func (h *backchannelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeLogoutError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentSize)
	if err := r.ParseForm(); err != nil {
		writeLogoutError(w, http.StatusBadRequest, "invalid_request", "unreadable form")
		return
	}
	raw := r.PostForm.Get("logout_token")
	if raw == "" {
		writeLogoutError(w, http.StatusBadRequest, "invalid_request", "logout_token is required")
		return
	}
	claims, err := h.verifier.VerifyLogoutToken(r.Context(), raw)
	if err != nil {
		h.logger.WarnContext(r.Context(), "back-channel token refused", "error", err)
		writeLogoutError(w, http.StatusBadRequest, "invalid_request", "invalid logout token")
		return
	}
	if !h.firstUse(claims) {
		h.logger.WarnContext(r.Context(), "back-channel token replayed", "jti", claims.ID)
		writeLogoutError(w, http.StatusBadRequest, "invalid_request", "logout token already used")
		return
	}
	if ev, ok := claims.Events[EventAccessChange]; ok && h.sink != nil {
		if ch, err := accessChangeFromEvent(claims, ev); err != nil {
			h.logger.WarnContext(r.Context(), "back-channel access_change event unreadable", "error", err)
		} else {
			h.sink.Record(ch)
		}
	}
	if _, ok := claims.Events[EventBackchannelLogout]; ok && h.sessions != nil {
		if err := h.endSessions(r.Context(), claims); err != nil {
			h.logger.ErrorContext(r.Context(), "back-channel logout: deleting sessions", "error", err)
			// Forget the jti so SystemAuth's retry is not taken for a replay.
			h.forget(claims.ID)
			writeLogoutError(w, http.StatusInternalServerError, "server_error", "sessions could not be ended")
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (h *backchannelHandler) endSessions(ctx context.Context, claims *LogoutTokenClaims) error {
	// With a sid only that session ends (OIDC Back-Channel Logout 1.0
	// section 2.7); with only a sub, every session of the subject does.
	if claims.SID != "" {
		_, err := h.sessions.DeleteBySID(ctx, claims.SID)
		return err
	}
	_, err := h.sessions.DeleteBySubject(ctx, claims.Subject)
	return err
}

func accessChangeFromEvent(claims *LogoutTokenClaims, raw json.RawMessage) (AccessChange, error) {
	var ev struct {
		OrganizationID string    `json:"organization_id"`
		ChangedAt      time.Time `json:"changed_at"`
		Reason         string    `json:"reason"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		return AccessChange{}, fmt.Errorf("decoding event: %w", err)
	}
	if claims.Subject == "" {
		return AccessChange{}, errors.New("access_change event without a sub")
	}
	if ev.ChangedAt.IsZero() {
		if claims.IssuedAt == nil {
			return AccessChange{}, errors.New("access_change event without a time")
		}
		ev.ChangedAt = claims.IssuedAt.Time
	}
	return AccessChange{PrincipalID: claims.Subject, OrganizationID: ev.OrganizationID, ChangedAt: ev.ChangedAt, Reason: ev.Reason}, nil
}

// firstUse records the token's jti and reports whether it is new. Entries
// are kept until the token would have expired anyway.
func (h *backchannelHandler) firstUse(claims *LogoutTokenClaims) bool {
	now := h.now()
	expires := now.Add(5 * time.Minute)
	if claims.ExpiresAt != nil {
		expires = claims.ExpiresAt.Add(time.Minute)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for jti, exp := range h.seen {
		if now.After(exp) {
			delete(h.seen, jti)
		}
	}
	if _, dup := h.seen[claims.ID]; dup {
		return false
	}
	h.seen[claims.ID] = expires
	return true
}

func (h *backchannelHandler) forget(jti string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.seen, jti)
}

func writeLogoutError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

var _ LogoutTokenVerifier = (*Client)(nil)
