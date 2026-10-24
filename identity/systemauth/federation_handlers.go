package systemauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ory/fosite"
)

// IdentitySyncHandler handles identity sync requests from SystemAuth.
// Apps must implement this interface to handle identity provisioning.
type IdentitySyncHandler interface {
	// SyncIdentity is called when SystemAuth wants to sync an identity to this app.
	// The handler should create/update/delete the local principal as appropriate.
	SyncIdentity(ctx context.Context, req *IdentitySyncRequest) (*IdentitySyncResponse, error)
}

// FederationHealthResponse is returned by the health endpoint.
type FederationHealthResponse struct {
	Status       string            `json:"status"`
	AppID        string            `json:"app_id"`
	Version      string            `json:"version"`
	Capabilities []string          `json:"capabilities"`
	Details      map[string]string `json:"details,omitempty"`
}

// FederationAuthenticator decides whether a request to a federation
// endpoint comes from the federation hub. It returns nil to admit the
// request.
type FederationAuthenticator func(r *http.Request) error

// ErrFederationUnauthorized is returned by authenticators for a request
// that does not prove it comes from the federation hub.
var ErrFederationUnauthorized = errors.New("systemauth: federation request not authorized")

// SharedSecretAuthenticator admits requests carrying the shared secret as
// a bearer token, compared in constant time. The secret should be long and
// random, and distinct per federated application.
func SharedSecretAuthenticator(secret string) FederationAuthenticator {
	want := []byte(secret)
	return func(r *http.Request) error {
		if len(want) == 0 {
			return ErrFederationUnauthorized
		}
		got := []byte(fosite.AccessTokenFromRequest(r))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return ErrFederationUnauthorized
		}
		return nil
	}
}

// TokenAuthenticator admits requests whose access token is a valid access
// token of this server carrying scope: Bearer for an unbound token, DPoP
// with a proof by its key for a DPoP-bound one.
func (s *Server) TokenAuthenticator(scope string) FederationAuthenticator {
	return func(r *http.Request) error {
		ar, authErr := s.authenticateAccessToken(r, s.requestURL(r))
		if authErr != nil || !ar.GetGrantedScopes().Has(scope) {
			return ErrFederationUnauthorized
		}
		return nil
	}
}

// FederationOption configures FederationEndpoints.
type FederationOption func(*FederationEndpoints)

// WithFederationAuthenticator sets how requests to the identity sync and
// lookup endpoints are authenticated. Without it those endpoints are not
// registered: they act on the request body as truth, so they must never
// be reachable unauthenticated.
func WithFederationAuthenticator(auth FederationAuthenticator) FederationOption {
	return func(f *FederationEndpoints) { f.authenticate = auth }
}

// FederationEndpoints provides SystemForge federation contract endpoints.
type FederationEndpoints struct {
	server       *Server
	syncHandler  IdentitySyncHandler
	authenticate FederationAuthenticator
	appID        string
	version      string
}

// NewFederationEndpoints creates federation endpoints for the server.
func NewFederationEndpoints(server *Server, syncHandler IdentitySyncHandler, opts ...FederationOption) *FederationEndpoints {
	appID := ""
	if server.config.Federation != nil {
		appID = server.config.Federation.AppID
	}

	f := &FederationEndpoints{
		server:      server,
		syncHandler: syncHandler,
		appID:       appID,
		version:     "1.0",
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// RegisterRoutes registers the federation endpoints on the server's router.
// The identity sync and lookup endpoints are registered only when an
// authenticator was configured (WithFederationAuthenticator).
func (f *FederationEndpoints) RegisterRoutes() {
	router := f.server.Router()

	// Health endpoint for SystemAuth to check app status
	router.Get("/systemforge/health", f.healthHandler)

	if f.authenticate == nil {
		f.server.logger.Error("federation identity sync and lookup endpoints not registered: no authenticator configured (see WithFederationAuthenticator)")
		return
	}

	// Identity sync endpoint
	router.Post("/systemforge/identity/sync", f.authenticated(f.identitySyncHandler))

	// Identity lookup endpoint (find local principal by global ID)
	router.Get("/systemforge/identity/lookup/{globalId}", f.authenticated(f.identityLookupHandler))
}

// authenticated requires the federation authenticator to admit the
// request before the handler runs.
func (f *FederationEndpoints) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f.authenticate(r); err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next(w, r)
	}
}

// healthHandler returns the health status of this app.
func (f *FederationEndpoints) healthHandler(w http.ResponseWriter, r *http.Request) {
	capabilities := []string{"identity"}
	if f.syncHandler != nil {
		capabilities = append(capabilities, "identity_sync")
	}

	resp := FederationHealthResponse{
		Status:       "healthy",
		AppID:        f.appID,
		Version:      f.version,
		Capabilities: capabilities,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// identitySyncHandler handles identity sync requests from SystemAuth.
func (f *FederationEndpoints) identitySyncHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if f.syncHandler == nil {
		http.Error(w, "identity sync not supported", http.StatusNotImplemented)
		return
	}

	var req IdentitySyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	resp, err := f.syncHandler.SyncIdentity(ctx, &req)
	if err != nil {
		f.server.logger.Error("identity sync failed", "error", err)
		errorResp := IdentitySyncResponse{
			Status: "failed",
			Error:  err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(errorResp)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// identityLookupHandler looks up a local principal by global identity ID.
func (f *FederationEndpoints) identityLookupHandler(w http.ResponseWriter, r *http.Request) {
	// This endpoint allows SystemAuth to verify identity mappings
	// Implementation depends on the app's user storage

	globalIDStr := chi.URLParam(r, "globalId")
	if globalIDStr == "" {
		http.Error(w, "globalId required", http.StatusBadRequest)
		return
	}

	globalID, err := uuid.Parse(globalIDStr)
	if err != nil {
		http.Error(w, "invalid globalId format", http.StatusBadRequest)
		return
	}

	// For now, return a stub - apps should implement proper lookup
	resp := map[string]interface{}{
		"global_identity_id": globalID,
		"app_id":             f.appID,
		"status":             "not_implemented",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// DefaultIdentitySyncHandler provides a basic implementation that creates local users.
type DefaultIdentitySyncHandler struct {
	storage Storage
}

// NewDefaultIdentitySyncHandler creates a sync handler that uses the storage.
func NewDefaultIdentitySyncHandler(storage Storage) *DefaultIdentitySyncHandler {
	return &DefaultIdentitySyncHandler{storage: storage}
}

// SyncIdentity implements IdentitySyncHandler.
func (h *DefaultIdentitySyncHandler) SyncIdentity(ctx context.Context, req *IdentitySyncRequest) (*IdentitySyncResponse, error) {
	if req.Identity == nil {
		return &IdentitySyncResponse{
			Status: "failed",
			Error:  "identity is required",
		}, nil
	}

	switch req.Action {
	case "create":
		return h.syncCreate(ctx, req.Identity), nil
	case "update":
		return h.syncUpdate(ctx, req.Identity, false, func(hp *HumanPrincipal) {
			hp.Email = req.Identity.Email
			hp.DisplayName = req.Identity.DisplayName
			hp.Active = req.Identity.Status == "active"
		}), nil
	case "delete":
		return h.syncUpdate(ctx, req.Identity, true, func(hp *HumanPrincipal) {
			hp.Active = false
		}), nil
	default:
		return &IdentitySyncResponse{
			Status: "failed",
			Error:  "unknown action: " + req.Action,
		}, nil
	}
}

func syncFailed(err error) *IdentitySyncResponse {
	return &IdentitySyncResponse{Status: "failed", Error: err.Error()}
}

// syncCreate creates a local human principal for a federated identity, or
// adopts an existing one with the same email, and links the federation
// identity to it so later updates and deletes resolve to the same principal.
func (h *DefaultIdentitySyncHandler) syncCreate(ctx context.Context, fi *GlobalIdentity) *IdentitySyncResponse {
	if fi.Email == "" {
		// Federated identities are adopted by email; never adopt a
		// human without one.
		return syncFailed(ErrEmailRequired)
	}
	hp, err := h.storage.GetHumanByEmail(ctx, fi.Email)
	switch {
	case errors.Is(err, ErrPrincipalNotFound):
		hp = &HumanPrincipal{
			Email:       fi.Email,
			DisplayName: fi.DisplayName,
			Active:      true,
		}
		if err := h.storage.CreateHuman(ctx, hp); err != nil {
			return syncFailed(err)
		}
	case err != nil:
		return syncFailed(err)
	}
	if err := h.storage.LinkExternalIdentity(ctx, hp.ID, FederationProvider, fi.ID.String()); err != nil {
		return syncFailed(err)
	}
	return &IdentitySyncResponse{LocalPrincipalID: hp.ID, Status: "synced"}
}

// syncUpdate applies change to the principal linked to a federated identity.
// When missingOK is set (deletes), an identity with no linked principal is
// already gone and reports synced; any other lookup error fails.
func (h *DefaultIdentitySyncHandler) syncUpdate(ctx context.Context, fi *GlobalIdentity, missingOK bool, change func(*HumanPrincipal)) *IdentitySyncResponse {
	hp, err := h.storage.GetHumanByExternalIdentity(ctx, FederationProvider, fi.ID.String())
	if err != nil {
		if missingOK && errors.Is(err, ErrPrincipalNotFound) {
			return &IdentitySyncResponse{Status: "synced"}
		}
		return syncFailed(err)
	}
	change(hp)
	if err := h.storage.UpdateHuman(ctx, hp); err != nil {
		return syncFailed(err)
	}
	return &IdentitySyncResponse{LocalPrincipalID: hp.ID, Status: "synced"}
}
