package connections

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	cf "github.com/plexusone/connectionforge"
	"github.com/plexusone/connectionforge/provider"
	"github.com/plexusone/connectionforge/service"

	"github.com/plexusone/systemforge/rls"
)

// OAuth scopes for the connections API, following the platform's
// "{app}:{resource}:{verb}" convention.
const (
	ScopeRead  = "systemforge:connections:read"
	ScopeWrite = "systemforge:connections:write"
)

// API paths.
const (
	ConnectionsPath = "/api/v1/organizations/{org}/connections"
	ProvidersPath   = "/api/v1/providers"
)

// Authenticator returns the principal behind an API request whose
// credentials carry scope. Its errors are written by the paired
// [AuthErrorWriter].
type Authenticator func(r *http.Request, scope string) (uuid.UUID, error)

// AuthErrorWriter writes the response for an [Authenticator] error.
type AuthErrorWriter func(w http.ResponseWriter, err error, scope string)

// maxBody bounds a request body.
const maxBody = 64 << 10

// Handler returns the connections API:
//
//	GET    /api/v1/providers
//	GET    /api/v1/organizations/{org}/connections
//	POST   /api/v1/organizations/{org}/connections
//	GET    /api/v1/organizations/{org}/connections/{id}
//	PATCH  /api/v1/organizations/{org}/connections/{id}
//	POST   /api/v1/organizations/{org}/connections/{id}/test
//	DELETE /api/v1/organizations/{org}/connections/{id}
//
// Each request is authenticated by auth with [ScopeRead] or [ScopeWrite], and
// runs with the organization in the path as the row-level security tenant. No
// response contains a credential.
func (c *Connections) Handler(auth Authenticator, writeAuthErr AuthErrorWriter, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &api{c: c, auth: auth, authErr: writeAuthErr, log: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+ProvidersPath, h.providers)
	mux.HandleFunc("GET "+ConnectionsPath, h.org(ScopeRead, h.list))
	mux.HandleFunc("POST "+ConnectionsPath, h.org(ScopeWrite, h.create))
	mux.HandleFunc("GET "+ConnectionsPath+"/{id}", h.org(ScopeRead, h.get))
	mux.HandleFunc("PATCH "+ConnectionsPath+"/{id}", h.org(ScopeWrite, h.rename))
	mux.HandleFunc("POST "+ConnectionsPath+"/{id}/test", h.org(ScopeWrite, h.test))
	mux.HandleFunc("DELETE "+ConnectionsPath+"/{id}", h.org(ScopeWrite, h.disconnect))
	return mux
}

type api struct {
	c       *Connections
	auth    Authenticator
	authErr AuthErrorWriter
	log     *slog.Logger
}

// call is an authenticated request in an organization.
type call struct {
	w     http.ResponseWriter
	r     *http.Request
	owner cf.OwnerID
	actor cf.Principal
}

func (h *api) org(scope string, fn func(call)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		pid, err := h.auth(r, scope)
		if err != nil {
			h.authErr(w, err, scope)
			return
		}
		org, err := uuid.Parse(r.PathValue("org"))
		if err != nil {
			writeError(w, http.StatusNotFound, "organization not found")
			return
		}
		ctx := rls.ContextWithTenantAndUser(r.Context(), org, pid)
		fn(call{
			w: w, r: r.WithContext(ctx), owner: OwnerFor(org),
			actor: cf.Principal{Kind: cf.PrincipalUser, ID: pid.String()},
		})
	}
}

func (h *api) providers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, err := h.auth(r, ScopeRead); err != nil {
		h.authErr(w, err, ScopeRead)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": h.c.Providers.Manifests()})
}

func (h *api) list(c call) {
	f := cf.Filter{Provider: c.r.URL.Query().Get("provider"), State: cf.State(c.r.URL.Query().Get("state"))}
	conns, err := h.c.Service.List(c.r.Context(), c.owner, c.actor, f)
	if err != nil {
		h.fail(c, err)
		return
	}
	writeJSON(c.w, http.StatusOK, map[string]any{"connections": conns})
}

// createRequest is the body of a create. Field values are secrets: they are
// validated with the provider, sealed and never returned.
type createRequest struct {
	Provider    string            `json:"provider"`
	AuthMethod  string            `json:"authMethod"`
	DisplayName string            `json:"displayName"`
	Fields      map[string]string `json:"fields"`
}

func (h *api) create(c call) {
	var req createRequest
	if !decode(c, &req) {
		return
	}
	fields := make(map[string]cf.Secret, len(req.Fields))
	for k, v := range req.Fields {
		fields[k] = cf.SecretString(v)
	}
	conn, err := h.c.Service.Create(c.r.Context(), service.CreateInput{
		Owner: c.owner, Actor: c.actor, Provider: req.Provider, AuthMethod: req.AuthMethod,
		DisplayName: req.DisplayName, Fields: fields,
	})
	h.respond(c, http.StatusCreated, conn, err)
}

func (h *api) get(c call) {
	conn, err := h.c.Service.Get(c.r.Context(), c.owner, c.actor, c.r.PathValue("id"))
	h.respond(c, http.StatusOK, conn, err)
}

func (h *api) rename(c call) {
	var req struct {
		DisplayName string `json:"displayName"`
	}
	if !decode(c, &req) {
		return
	}
	conn, err := h.c.Service.Rename(c.r.Context(), c.owner, c.actor, c.r.PathValue("id"), req.DisplayName)
	h.respond(c, http.StatusOK, conn, err)
}

func (h *api) test(c call) {
	conn, err := h.c.Service.Test(c.r.Context(), c.owner, c.actor, c.r.PathValue("id"))
	h.respond(c, http.StatusOK, conn, err)
}

func (h *api) disconnect(c call) {
	conn, err := h.c.Service.Disconnect(c.r.Context(), c.owner, c.actor, c.r.PathValue("id"))
	h.respond(c, http.StatusOK, conn, err)
}

// respond writes conn, or the error. A change whose audit event was lost
// still succeeded: it is returned, and the gap is logged as an incident.
func (h *api) respond(c call, status int, conn cf.Connection, err error) {
	if errors.Is(err, service.ErrNotAudited) {
		h.log.ErrorContext(c.r.Context(), "connections: change not audited", "error", err, "connection", conn.ID)
		err = nil
	}
	if err != nil {
		h.fail(c, err)
		return
	}
	writeJSON(c.w, status, conn)
}

// fail maps an error to a status. A refused view is reported as not found,
// so a response does not reveal that a connection exists.
func (h *api) fail(c call, err error) {
	switch {
	case errors.Is(err, cf.ErrNotFound):
		writeError(c.w, http.StatusNotFound, "connection not found")
	case errors.Is(err, cf.ErrDenied) && c.r.Method == http.MethodGet:
		writeError(c.w, http.StatusNotFound, "connection not found")
	case errors.Is(err, cf.ErrDenied):
		writeError(c.w, http.StatusForbidden, "not allowed")
	case errors.Is(err, service.ErrInvalidInput), errors.Is(err, provider.ErrUnknownProvider):
		writeError(c.w, http.StatusBadRequest, err.Error())
	case errors.Is(err, cf.ErrInvalidCredential), errors.Is(err, cf.ErrInsufficientScope):
		// The message is classified: status and request ID, never a body.
		writeError(c.w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, cf.ErrRateLimited), errors.Is(err, cf.ErrTransient):
		writeError(c.w, http.StatusBadGateway, err.Error())
	case errors.Is(err, cf.ErrNotUsable), errors.Is(err, cf.ErrConflict), errors.Is(err, cf.ErrInvalidTransition):
		writeError(c.w, http.StatusConflict, err.Error())
	default:
		h.log.ErrorContext(c.r.Context(), "connections: request failed", "error", err)
		writeError(c.w, http.StatusInternalServerError, "internal error")
	}
}

func decode(c call, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(c.w, c.r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(c.w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The status is sent; a failed write means the client went away.
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return
	}
}
