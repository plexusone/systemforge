package managedprincipal

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/session/ratelimit"
)

// LoginTokenView is a login token as a manager sees it; it never carries
// the token value.
type LoginTokenView struct {
	ID         uuid.UUID  `json:"id"`
	Prefix     string     `json:"prefix"`
	Name       string     `json:"name,omitempty"`
	IssuedBy   uuid.UUID  `json:"issued_by"`
	SingleUse  bool       `json:"single_use"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP string     `json:"last_used_ip,omitempty"`
}

// NewHandler returns the managed-principal API. Mount it under a prefix,
// such as /managed-principals, behind requestprincipal.Middleware, which
// identifies the calling principal. Every route goes through the same
// service operations, and so the same authorizer checks, as the Go API.
//
// Managing a principal:
//
//	GET    /                                         the caller's managed principals (?after=&limit=)
//	POST   /                                         create (actor must be a manager)
//	GET    /{principalID}/managers                   view_profile
//	POST   /{principalID}/managers                   add a manager; manage_managers
//	DELETE /{principalID}/managers/{managerID}/{role} remove a manager; manage_managers
//	POST   /{principalID}/release                    end management; manage_managers
//	DELETE /{principalID}                            delete; manage_account
//	POST   /{principalID}/claims                     issue a claim code; manage_credentials
//	POST   /claims/redeem                            the caller redeems a claim code
//
// Consent to be managed:
//
//	POST   /manager-invites                          the caller offers to manage a verified address
//	POST   /manager-invites/accept                   the caller accepts, entering management
//	POST   /manager-invites/decline                  the caller declines
//	DELETE /manager-invites/{inviteID}               the inviter withdraws it
//
// Credentials and sessions, each requiring manage_credentials on the
// managed principal:
//
//	GET    /{principalID}/login-tokens
//	POST   /{principalID}/login-tokens               issue; the caller is an active manager
//	DELETE /{principalID}/login-tokens/{credentialID}
//	GET    /{principalID}/sessions
//	DELETE /{principalID}/sessions/{kind}/{sessionID}
//	POST   /{principalID}/revoke-all
//
// Options put the handler in relying-party mode (WithRequestClient) and
// rate limit the code routes (WithCodeRateLimit).
func NewHandler(svc *Service, opts ...HandlerOption) http.Handler {
	h := &handler{svc: svc}
	for _, opt := range opts {
		opt(h)
	}
	r := chi.NewRouter()
	r.Get("/", h.listManaged)
	r.Post("/", h.create)
	r.Post("/claims/redeem", h.redeemClaim)
	r.Post("/manager-invites", h.inviteManager)
	r.Post("/manager-invites/accept", h.acceptInvite)
	r.Post("/manager-invites/decline", h.declineInvite)
	r.Delete("/manager-invites/{inviteID}", h.revokeInvite)
	r.Delete("/{principalID}", h.delete)
	r.Get("/{principalID}/managers", h.listManagers)
	r.Post("/{principalID}/managers", h.addManager)
	r.Delete("/{principalID}/managers/{managerID}/{role}", h.removeManager)
	r.Post("/{principalID}/release", h.release)
	r.Post("/{principalID}/claims", h.issueClaim)
	r.Get("/{principalID}/login-tokens", h.listLoginTokens)
	r.Post("/{principalID}/login-tokens", h.issueLoginToken)
	r.Delete("/{principalID}/login-tokens/{credentialID}", h.revokeLoginToken)
	r.Get("/{principalID}/sessions", h.listSessions)
	r.Delete("/{principalID}/sessions/{kind}/{sessionID}", h.revokeSession)
	r.Post("/{principalID}/revoke-all", h.revokeAll)
	return r
}

type handler struct {
	svc       *Service
	clientOf  func(*http.Request) (string, bool)
	codeRates ratelimit.Storage
	codeLimit ratelimit.Limit
}

// caller returns the calling principal, writing an error response when
// there is none.
func (h *handler) caller(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	rp, found := requestprincipal.FromContext(r.Context())
	if !found {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return uuid.Nil, false
	}
	actor, err := uuid.Parse(rp.PrincipalID)
	if err != nil {
		// Credentials issued elsewhere carry issuer-qualified subjects,
		// which cannot manage SystemForge principals.
		writeError(w, http.StatusForbidden, "forbidden")
		return uuid.Nil, false
	}
	return actor, true
}

// ids returns the calling principal and the managed principal of the
// request, writing an error response when either is missing.
func (h *handler) ids(w http.ResponseWriter, r *http.Request) (actor, managed uuid.UUID, ok bool) {
	actor, ok = h.caller(w, r)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	managed, err := uuid.Parse(chi.URLParam(r, "principalID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return uuid.Nil, uuid.Nil, false
	}
	return actor, managed, true
}

func (h *handler) listLoginTokens(w http.ResponseWriter, r *http.Request) {
	actor, managed, ok := h.ids(w, r)
	if !ok {
		return
	}
	creds, err := h.svc.ListLoginTokens(r.Context(), actor, managed)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := make([]LoginTokenView, 0, len(creds))
	for _, c := range creds {
		issuer, err := credential.LoginTokenIssuedBy(c)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		out = append(out, LoginTokenView{
			ID: c.ID, Prefix: c.Identifier, Name: c.Name, IssuedBy: issuer,
			SingleUse: credential.LoginTokenSingleUse(c), CreatedAt: c.CreatedAt,
			ExpiresAt: c.ExpiresAt, LastUsedAt: c.LastUsedAt, LastUsedIP: c.LastUsedIP,
		})
	}
	h.writeJSON(w, r, map[string]any{"login_tokens": out})
}

func (h *handler) revokeLoginToken(w http.ResponseWriter, r *http.Request) {
	actor, managed, ok := h.ids(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "credentialID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err := h.svc.RevokeLoginToken(r.Context(), actor, managed, id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) listSessions(w http.ResponseWriter, r *http.Request) {
	actor, managed, ok := h.ids(w, r)
	if !ok {
		return
	}
	sessions, err := h.svc.ListSessions(r.Context(), actor, managed)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if sessions == nil {
		sessions = []Session{}
	}
	h.writeJSON(w, r, map[string]any{"sessions": sessions})
}

func (h *handler) revokeSession(w http.ResponseWriter, r *http.Request) {
	actor, managed, ok := h.ids(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	kind := SessionKind(chi.URLParam(r, "kind"))
	if err := h.svc.RevokeSession(r.Context(), actor, managed, kind, id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) revokeAll(w http.ResponseWriter, r *http.Request) {
	actor, managed, ok := h.ids(w, r)
	if !ok {
		return
	}
	if err := h.svc.RevokeAll(r.Context(), actor, managed); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	if h.remote() && (errors.Is(err, ErrNotFound) || errors.Is(err, ErrNotManaged)) {
		// Callers from other applications get one answer whether a
		// principal does not exist, is not managed, or is not theirs, so
		// the API cannot be asked who is a managed principal.
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	switch {
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrNotAllowed), errors.Is(err, ErrNotManager):
		writeError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrNotManaged):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, ErrInvalidClaim), errors.Is(err, ErrInvalidInvite):
		// One answer for every reason a code cannot be used.
		writeError(w, http.StatusBadRequest, "invalid code")
	case errors.Is(err, ErrDisplayNameRequired), errors.Is(err, ErrNoManagers), errors.Is(err, ErrInvalidManager),
		errors.Is(err, ErrInvalidRole), errors.Is(err, ErrEmailRequired), errors.Is(err, ErrInviteEmailRequired),
		errors.Is(err, credential.ErrInvalidExpiry):
		writeError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), "managedprincipal: "))
	case errors.Is(err, ErrLastManager), errors.Is(err, ErrEmailInUse), errors.Is(err, ErrHasEmail),
		errors.Is(err, ErrEmailNotVerified), errors.Is(err, ErrAlreadyManaged), errors.Is(err, ErrManagesOthers):
		writeError(w, http.StatusConflict, strings.TrimPrefix(err.Error(), "managedprincipal: "))
	default:
		h.svc.logger.ErrorContext(r.Context(), "managedprincipal: request failed", "path", r.URL.Path, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func (h *handler) writeJSON(w http.ResponseWriter, r *http.Request, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status is already sent; the client sees a truncated body.
		h.svc.logger.ErrorContext(r.Context(), "managedprincipal: write response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body, err := json.Marshal(map[string]string{"error": msg})
	if err != nil {
		panic(err) // a map of strings always marshals
	}
	if _, err := w.Write(body); err != nil {
		slog.Default().Error("managedprincipal: write error response", "error", err)
	}
}
