package systemauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
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

// AccessChangeScope returns which organizations' access changes a client
// may read from the replay endpoint: orgIDs, or every organization when
// all is true (a platform operator's client, or a deployment serving a
// single application). Changes that name no organization (a principal
// deactivated, its sessions revoked) concern every relying party and are
// always included.
type AccessChangeScope func(ctx context.Context, clientID string) (orgIDs []uuid.UUID, all bool, err error)

// AllOrganizations is an AccessChangeScope giving every client the whole
// feed. Use it only when every client granted access_changes:read may see
// changes of every organization, as in a deployment of one application.
func AllOrganizations(context.Context, string) ([]uuid.UUID, bool, error) {
	return nil, true, nil
}

// WithAccessChanges serves GET /access-changes?since=<RFC 3339> from lister
// to clients holding a token with the access_changes:read scope, each
// limited to the organizations scope returns for it. A relying party that
// restarted calls it to rebuild its revocation cache before serving.
// Without it, or with a nil scope, the endpoint answers 501. In a
// deployment of several applications, scope each client to the
// organizations that use its application, so one application does not
// learn about another's members.
func WithAccessChanges(lister AccessChangeLister, scope AccessChangeScope) Option {
	return func(s *Server) {
		s.accessChanges = lister
		s.accessScope = scope
	}
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
	if s.accessChanges == nil || s.accessScope == nil {
		http.Error(w, "access changes are not configured", http.StatusNotImplemented)
		return
	}
	clientID := ar.GetClient().GetID()
	orgIDs, all, err := s.accessScope(ctx, clientID)
	if err != nil {
		logger.Error("access changes: resolving the client's organizations", "client_id", clientID, "error", err)
		http.Error(w, "could not read access changes", http.StatusInternalServerError)
		return
	}
	visible := make(map[uuid.UUID]bool, len(orgIDs))
	for _, id := range orgIDs {
		visible[id] = true
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
	// The page is filtered to the client's organizations; paging follows
	// the unfiltered page, so a filtered page may be short or empty and
	// still carry NextSince.
	resp := AccessChangesResponse{Changes: make([]AccessChangeResponse, 0, len(changes))}
	for _, c := range changes {
		if c.OrganizationID != nil && !all && !visible[*c.OrganizationID] {
			continue
		}
		item := AccessChangeResponse{PrincipalID: c.PrincipalID.String(), ChangedAt: c.ChangedAt, Reason: string(c.Reason)}
		if c.OrganizationID != nil {
			item.OrganizationID = c.OrganizationID.String()
		}
		resp.Changes = append(resp.Changes, item)
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
