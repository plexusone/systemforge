package managedprincipal

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/requestprincipal"
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

// NewHandler returns the manager visibility API. Mount it under a prefix,
// such as /managed-principals, behind requestprincipal.Middleware, which
// identifies the calling manager:
//
//	GET    /{principalID}/login-tokens
//	DELETE /{principalID}/login-tokens/{credentialID}
//	GET    /{principalID}/sessions
//	DELETE /{principalID}/sessions/{kind}/{sessionID}
//	POST   /{principalID}/revoke-all
//
// Every route requires manage_credentials on the managed principal.
func NewHandler(svc *Service) http.Handler {
	h := &handler{svc: svc}
	r := chi.NewRouter()
	r.Get("/{principalID}/login-tokens", h.listLoginTokens)
	r.Delete("/{principalID}/login-tokens/{credentialID}", h.revokeLoginToken)
	r.Get("/{principalID}/sessions", h.listSessions)
	r.Delete("/{principalID}/sessions/{kind}/{sessionID}", h.revokeSession)
	r.Post("/{principalID}/revoke-all", h.revokeAll)
	return r
}

type handler struct {
	svc *Service
}

// ids returns the calling principal and the managed principal of the
// request, writing an error response when either is missing.
func (h *handler) ids(w http.ResponseWriter, r *http.Request) (actor, managed uuid.UUID, ok bool) {
	rp, found := requestprincipal.FromContext(r.Context())
	if !found {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return uuid.Nil, uuid.Nil, false
	}
	actor, err := uuid.Parse(rp.PrincipalID)
	if err != nil {
		// Credentials issued elsewhere carry issuer-qualified subjects,
		// which cannot manage SystemForge principals.
		writeError(w, http.StatusForbidden, "forbidden")
		return uuid.Nil, uuid.Nil, false
	}
	managed, err = uuid.Parse(chi.URLParam(r, "principalID"))
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
	switch {
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrNotManaged):
		writeError(w, http.StatusNotFound, "not found")
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
