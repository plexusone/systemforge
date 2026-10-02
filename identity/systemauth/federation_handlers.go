package systemauth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
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
	Status      string            `json:"status"`
	AppID       string            `json:"app_id"`
	Version     string            `json:"version"`
	Capabilities []string         `json:"capabilities"`
	Details     map[string]string `json:"details,omitempty"`
}

// FederationEndpoints provides SystemForge federation contract endpoints.
type FederationEndpoints struct {
	server      *Server
	syncHandler IdentitySyncHandler
	appID       string
	version     string
}

// NewFederationEndpoints creates federation endpoints for the server.
func NewFederationEndpoints(server *Server, syncHandler IdentitySyncHandler) *FederationEndpoints {
	appID := ""
	if server.config.Federation != nil {
		appID = server.config.Federation.AppID
	}

	return &FederationEndpoints{
		server:      server,
		syncHandler: syncHandler,
		appID:       appID,
		version:     "1.0",
	}
}

// RegisterRoutes registers the federation endpoints on the server's router.
func (f *FederationEndpoints) RegisterRoutes() {
	router := f.server.Router()

	// Health endpoint for SystemAuth to check app status
	router.Get("/systemforge/health", f.healthHandler)

	// Identity sync endpoint
	router.Post("/systemforge/identity/sync", f.identitySyncHandler)

	// Identity lookup endpoint (find local principal by global ID)
	router.Get("/systemforge/identity/lookup/{globalId}", f.identityLookupHandler)
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

	// Verify the request is from SystemAuth (in production, verify JWT or signature)
	// For now, we trust the request if it has a valid format

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

	globalIDStr := r.PathValue("globalId")
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
		// Check if user already exists
		_, err := h.storage.GetUserByEmail(ctx, req.Identity.Email)
		if err == nil {
			// User exists, return the existing ID
			user, _ := h.storage.GetUserByEmail(ctx, req.Identity.Email)
			return &IdentitySyncResponse{
				LocalPrincipalID: user.ID,
				Status:           "synced",
			}, nil
		}

		// Create new user
		user := &User{
			ID:           uuid.New(),
			Email:        req.Identity.Email,
			Name:         req.Identity.DisplayName,
			Active:       true,
			Federated:    true,
			FederationID: &req.Identity.ID,
		}

		if err := h.storage.CreateUser(ctx, user); err != nil {
			return &IdentitySyncResponse{
				Status: "failed",
				Error:  err.Error(),
			}, nil
		}

		return &IdentitySyncResponse{
			LocalPrincipalID: user.ID,
			Status:           "synced",
		}, nil

	case "update":
		// Find user by federation ID
		user, err := h.storage.GetUserByFederationID(ctx, req.Identity.ID)
		if err != nil {
			return &IdentitySyncResponse{
				Status: "failed",
				Error:  "user not found",
			}, nil
		}

		// Update user fields
		user.Email = req.Identity.Email
		user.Name = req.Identity.DisplayName
		user.Active = req.Identity.Status == "active"

		if err := h.storage.UpdateUser(ctx, user); err != nil {
			return &IdentitySyncResponse{
				Status: "failed",
				Error:  err.Error(),
			}, nil
		}

		return &IdentitySyncResponse{
			LocalPrincipalID: user.ID,
			Status:           "synced",
		}, nil

	case "delete":
		// Find and deactivate user
		user, err := h.storage.GetUserByFederationID(ctx, req.Identity.ID)
		if err != nil {
			return &IdentitySyncResponse{
				Status: "synced", // Already gone
			}, nil
		}

		user.Active = false
		if err := h.storage.UpdateUser(ctx, user); err != nil {
			return &IdentitySyncResponse{
				Status: "failed",
				Error:  err.Error(),
			}, nil
		}

		return &IdentitySyncResponse{
			LocalPrincipalID: user.ID,
			Status:           "synced",
		}, nil

	default:
		return &IdentitySyncResponse{
			Status: "failed",
			Error:  "unknown action: " + req.Action,
		}, nil
	}
}

// User represents a local user identity.
type User struct {
	ID           uuid.UUID  `json:"id"`
	Email        string     `json:"email"`
	EmailVerified bool      `json:"email_verified,omitempty"`
	Name         string     `json:"name"`
	GivenName    string     `json:"given_name,omitempty"`
	FamilyName   string     `json:"family_name,omitempty"`
	Picture      string     `json:"picture,omitempty"`
	Locale       string     `json:"locale,omitempty"`
	Active       bool       `json:"active"`
	Federated    bool       `json:"federated"`
	FederationID *uuid.UUID `json:"federation_id,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	CreatedAt    time.Time  `json:"created_at,omitzero"`
	UpdatedAt    time.Time  `json:"updated_at,omitzero"`
}
