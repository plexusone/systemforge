package systemauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/accesschange"
)

// AccessChangesPath is the path of the replay endpoint (ADR-010 decision 6).
const AccessChangesPath = "/access-changes"

// AccessChangesScope is the scope a client-credentials token needs to read
// the replay endpoint.
const AccessChangesScope = "access_changes:read"

// Replay page sizes.
const (
	defaultAccessChangesLimit = 1000
	maxAccessChangesLimit     = 5000
)

// AccessChangeLister lists recorded access changes. *accesschange.Source
// implements it.
type AccessChangeLister interface {
	List(ctx context.Context, since time.Time, limit int) ([]accesschange.Change, error)
}

// WithAccessChanges serves GET /access-changes?since=<RFC 3339> from lister
// to clients holding a token with the access_changes:read scope. A
// relying party that restarted calls it to rebuild its revocation cache
// before serving. Without it the endpoint answers 501.
func WithAccessChanges(lister AccessChangeLister) Option {
	return func(s *Server) { s.accessChanges = lister }
}

// AccessChangeResponse is one change in the replay response.
type AccessChangeResponse struct {
	PrincipalID    string    `json:"principal_id"`
	OrganizationID string    `json:"organization_id,omitempty"`
	ChangedAt      time.Time `json:"changed_at"`
	Reason         string    `json:"reason"`
}

// AccessChangesResponse is the replay response. NextSince is set when more
// changes follow; pass it as since to read them.
type AccessChangesResponse struct {
	Changes   []AccessChangeResponse `json:"changes"`
	NextSince *time.Time             `json:"next_since,omitempty"`
}

// accessChangesEndpoint serves GET /access-changes?since=&limit=.
func (s *Server) accessChangesEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)

	token := bearerToken(r)
	if token == "" {
		writeBearerError(w, http.StatusUnauthorized, "", "", "")
		return
	}
	ar, err := s.introspect(ctx, token, fosite.AccessToken, s.Session(""))
	if err != nil {
		logger.Debug("access changes: invalid access token", "error", err)
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "The access token is invalid, expired or revoked.", "")
		return
	}
	if !ar.GetGrantedScopes().Has(AccessChangesScope) {
		writeBearerError(w, http.StatusForbidden, "insufficient_scope", "The access token was not granted the access_changes:read scope.", AccessChangesScope)
		return
	}
	if s.accessChanges == nil {
		http.Error(w, "access changes are not configured", http.StatusNotImplemented)
		return
	}
	since, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("since"))
	if err != nil {
		http.Error(w, "since must be an RFC 3339 timestamp", http.StatusBadRequest)
		return
	}
	limit := defaultAccessChangesLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
			return
		}
		limit = min(n, maxAccessChangesLimit)
	}
	changes, err := s.accessChanges.List(ctx, since, limit)
	if err != nil {
		logger.Error("access changes: reading changes", "error", err)
		http.Error(w, "could not read access changes", http.StatusInternalServerError)
		return
	}
	resp := AccessChangesResponse{Changes: make([]AccessChangeResponse, len(changes))}
	for i, c := range changes {
		resp.Changes[i] = AccessChangeResponse{PrincipalID: c.PrincipalID.String(), ChangedAt: c.ChangedAt, Reason: string(c.Reason)}
		if c.OrganizationID != nil {
			resp.Changes[i].OrganizationID = c.OrganizationID.String()
		}
	}
	if len(changes) == limit {
		next := changes[len(changes)-1].ChangedAt.Add(-time.Nanosecond)
		if next.After(since) { // a full page of one timestamp cannot be advanced past
			resp.NextSince = &next
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Error("writing access changes response", "error", err)
	}
}
