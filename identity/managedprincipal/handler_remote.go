package managedprincipal

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/session/ratelimit"
)

// Scope is the OAuth scope an access token needs to call the
// managed-principal API that SystemAuth serves to relying parties.
const Scope = "systemforge:managed_principals"

// DefaultCodeLimit is the default per-caller limit on redeeming claim codes
// and answering manager invitations. Codes carry 160 random bits, so the
// limit is defense in depth, sized for a person entering a code by hand.
var DefaultCodeLimit = ratelimit.PerMinute(10)

// HandlerOption configures NewHandler.
type HandlerOption func(*handler)

// WithRequestClient puts the handler in relying-party mode, for an API that
// applications in other processes call with a manager's access token. The
// OAuth client that creation, login-token issue, and invitations are checked
// against is the one clientOf returns for the request, the client the token
// was issued to; a body client_id that differs is refused. Creation accepts
// only the caller as the initial manager, and adding a manager directly is
// refused: further managers join through invitations and claims, which ask
// for their consent.
func WithRequestClient(clientOf func(*http.Request) (string, bool)) HandlerOption {
	return func(h *handler) { h.clientOf = clientOf }
}

// WithCodeRateLimit limits, per calling principal, the requests that
// present a code: redeeming a claim and accepting or declining a manager
// invitation. Over the limit the handler answers 429 with Retry-After.
func WithCodeRateLimit(storage ratelimit.Storage, limit ratelimit.Limit) HandlerOption {
	return func(h *handler) {
		h.codeRates = storage
		h.codeLimit = limit
	}
}

// RequestClientFromPrincipal returns the OAuth client of the request's
// principal from Claims["client_id"], which systemauth's
// BearerAuthenticator sets. Pass it to WithRequestClient.
func RequestClientFromPrincipal(r *http.Request) (string, bool) {
	p, ok := requestprincipal.FromContext(r.Context())
	if !ok {
		return "", false
	}
	id, ok := p.Claims["client_id"].(string)
	return id, ok && id != ""
}

// remote reports whether the handler serves relying parties.
func (h *handler) remote() bool { return h.clientOf != nil }

// client returns the OAuth client of a request: the authenticated client in
// relying-party mode, where a different named client is refused, and the
// named client otherwise, which the service checks. It writes an error
// response when it returns false.
func (h *handler) client(w http.ResponseWriter, r *http.Request, named string) (string, bool) {
	if !h.remote() {
		return named, true
	}
	id, ok := h.clientOf(r)
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return "", false
	}
	if named != "" && named != id {
		writeError(w, http.StatusBadRequest, "client_id does not match the access token")
		return "", false
	}
	return id, true
}

// allowCode applies the code rate limit to the calling principal.
func (h *handler) allowCode(w http.ResponseWriter, r *http.Request, actor uuid.UUID) bool {
	if h.codeRates == nil {
		return true
	}
	res, err := h.codeRates.Allow(r.Context(), "managedprincipal:code:"+actor.String(), h.codeLimit)
	if err != nil {
		// Failing closed: a code endpoint without its limit is the one
		// that can be guessed against.
		h.svc.logger.ErrorContext(r.Context(), "managedprincipal: rate limit", "error", err)
		writeError(w, http.StatusServiceUnavailable, "try again later")
		return false
	}
	if !res.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(res.RetryAfter.Round(time.Second)/time.Second))))
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return false
	}
	return true
}

func (h *handler) listManaged(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.caller(w, r)
	if !ok {
		return
	}
	var after uuid.UUID
	if v := r.URL.Query().Get("after"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid after")
			return
		}
		after = id
	}
	limit := MaxListLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		limit = n
	}
	out, err := h.svc.ListManagedBy(r.Context(), actor, after, limit)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeJSON(w, r, map[string]any{"managed_principals": out})
}

// IssueLoginTokenRequest is the body of POST /{principalID}/login-tokens.
type IssueLoginTokenRequest struct {
	// ClientID is the OAuth client requesting the token. In relying-party
	// mode it is the access token's client and may be omitted.
	ClientID string `json:"client_id,omitempty"`
	// Name optionally labels the token, such as the card or device.
	Name string `json:"name,omitempty"`
	// SingleUse makes the token valid for one sign-in.
	SingleUse bool `json:"single_use,omitempty"`
	// ExpiresAt optionally sets the expiry; it is clamped to the ceiling.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// IssuedLoginToken is the response to POST /{principalID}/login-tokens. The
// token value is returned only here.
type IssuedLoginToken struct {
	ID        uuid.UUID  `json:"id"`
	Token     string     `json:"token"`
	Prefix    string     `json:"prefix"`
	SingleUse bool       `json:"single_use"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (h *handler) issueLoginToken(w http.ResponseWriter, r *http.Request) {
	actor, managed, ok := h.ids(w, r)
	if !ok {
		return
	}
	var req IssueLoginTokenRequest
	if !h.decode(w, r, &req) {
		return
	}
	clientID, ok := h.client(w, r, req.ClientID)
	if !ok {
		return
	}
	tok, err := h.svc.IssueLoginToken(r.Context(), IssueLoginTokenInput{
		ManagedID: managed, ClientID: clientID, IssuedBy: actor,
		ExpiresAt: req.ExpiresAt, SingleUse: req.SingleUse, Name: req.Name,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeCreated(w, r, IssuedLoginToken{
		ID: tok.Credential.ID, Token: tok.PlainToken, Prefix: tok.Prefix,
		SingleUse: credential.LoginTokenSingleUse(tok.Credential), ExpiresAt: tok.Credential.ExpiresAt,
	})
}
