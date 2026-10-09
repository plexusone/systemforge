package systemauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
)

// The organization claims of ADR-007.
const (
	// OrgsClaim is the claim listing the organizations a principal belongs
	// to, with the principal's role and application roles in each.
	OrgsClaim = "orgs"
	// OrgsTruncatedClaim is true when OrgsClaim omits organizations
	// because the principal belongs to more than MaxOrgsInToken.
	OrgsTruncatedClaim = "orgs_truncated"
	// MaxOrgsInToken is the most organizations a token or the userinfo
	// claim carries. GET /oauth/userinfo/memberships returns them all.
	MaxOrgsInToken = 50
	// MembershipsPath is the paginated memberships endpoint.
	MembershipsPath = UserInfoPath + "/memberships"

	// DefaultMembershipsPageSize and MaxMembershipsPageSize bound the
	// memberships endpoint's page.
	DefaultMembershipsPageSize = 50
	MaxMembershipsPageSize     = 100
)

// OrgClaim is one organization in the orgs claim. The compact form, used
// in JWT access tokens, leaves Slug, Name and Type empty so they are
// omitted.
type OrgClaim struct {
	ID   string `json:"id"`
	Slug string `json:"slug,omitempty"`
	Name string `json:"name,omitempty"`
	// Type is personal, team or enterprise.
	Type string `json:"type,omitempty"`
	// Role is the principal's organization role: owner, admin, member or
	// collaborator.
	Role string `json:"role"`
	// Apps maps each application the principal may open in this
	// organization to the principal's role in it. An application absent
	// from the map is one the principal may not open.
	Apps map[string]string `json:"apps"`
}

// OrgsResult is the orgs claim of one principal.
type OrgsResult struct {
	Orgs      []OrgClaim
	Truncated bool
}

// OrgsSource supplies the orgs claim. EntOrgsSource is the standard
// implementation.
type OrgsSource interface {
	// OrgsClaim returns the principal's organizations, personal first and
	// then by most recent membership, at most MaxOrgsInToken of them. The
	// compact form omits slug, name and type.
	OrgsClaim(ctx context.Context, principalID uuid.UUID, compact bool) (OrgsResult, error)
	// Memberships returns one page of the principal's organizations in
	// the full form and the same order, limit at most, starting after the
	// organization cursor names ("" for the first page). next is empty on
	// the last page.
	Memberships(ctx context.Context, principalID uuid.UUID, limit int, cursor string) (page []OrgClaim, next string, err error)
}

// AppRoleResolver reports a principal's application roles in an
// organization. identity/approle.Service implements it.
type AppRoleResolver interface {
	EffectiveRoles(ctx context.Context, principalID, organizationID uuid.UUID) (map[string]string, error)
}

// ErrInvalidCursor means a memberships cursor does not name a membership
// of the principal.
var ErrInvalidCursor = errors.New("systemauth: invalid memberships cursor")

// EntOrgsSource builds the orgs claim from memberships stored through Ent
// and application roles from an AppRoleResolver.
type EntOrgsSource struct {
	client *ent.Client
	roles  AppRoleResolver
}

var _ OrgsSource = (*EntOrgsSource)(nil)

// NewEntOrgsSource returns an OrgsSource over client. roles supplies the
// apps of each organization; with nil every organization carries an empty
// apps map.
func NewEntOrgsSource(client *ent.Client, roles AppRoleResolver) *EntOrgsSource {
	return &EntOrgsSource{client: client, roles: roles}
}

// orgEntry is a membership with the data ordering and the claim need.
type orgEntry struct {
	membershipID uuid.UUID
	createdAt    time.Time
	org          *ent.Organization
	role         string
}

// entries lists the principal's active memberships in active
// organizations, personal first, then newest membership first.
func (s *EntOrgsSource) entries(ctx context.Context, principalID uuid.UUID) ([]orgEntry, error) {
	rows, err := s.client.PrincipalMembership.Query().
		Where(
			principalmembership.PrincipalID(principalID),
			principalmembership.Active(true),
			principalmembership.HasOrganizationWith(organization.Active(true)),
		).
		WithOrganization().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("systemauth: reading memberships: %w", err)
	}
	out := make([]orgEntry, 0, len(rows))
	for _, m := range rows {
		if m.Edges.Organization == nil {
			continue
		}
		out = append(out, orgEntry{membershipID: m.ID, createdAt: m.CreatedAt, org: m.Edges.Organization, role: m.Role})
	}
	sort.Slice(out, func(i, j int) bool {
		pi, pj := out[i].org.OrgType == organization.OrgTypePersonal, out[j].org.OrgType == organization.OrgTypePersonal
		if pi != pj {
			return pi
		}
		if !out[i].createdAt.Equal(out[j].createdAt) {
			return out[i].createdAt.After(out[j].createdAt)
		}
		return out[i].membershipID.String() > out[j].membershipID.String()
	})
	return out, nil
}

func (s *EntOrgsSource) claim(ctx context.Context, principalID uuid.UUID, e orgEntry, compact bool) (OrgClaim, error) {
	c := OrgClaim{ID: e.org.ID.String(), Role: e.role, Apps: map[string]string{}}
	if !compact {
		c.Slug, c.Name, c.Type = e.org.Slug, e.org.Name, string(e.org.OrgType)
	}
	if s.roles != nil {
		apps, err := s.roles.EffectiveRoles(ctx, principalID, e.org.ID)
		if err != nil {
			return OrgClaim{}, fmt.Errorf("systemauth: application roles in %s: %w", e.org.ID, err)
		}
		for app, role := range apps {
			c.Apps[app] = role
		}
	}
	return c, nil
}

// OrgsClaim implements OrgsSource.
func (s *EntOrgsSource) OrgsClaim(ctx context.Context, principalID uuid.UUID, compact bool) (OrgsResult, error) {
	list, err := s.entries(ctx, principalID)
	if err != nil {
		return OrgsResult{}, err
	}
	res := OrgsResult{Orgs: []OrgClaim{}}
	if len(list) > MaxOrgsInToken {
		list, res.Truncated = list[:MaxOrgsInToken], true
	}
	for _, e := range list {
		c, err := s.claim(ctx, principalID, e, compact)
		if err != nil {
			return OrgsResult{}, err
		}
		res.Orgs = append(res.Orgs, c)
	}
	return res, nil
}

// Memberships implements OrgsSource. The cursor is an organization ID.
func (s *EntOrgsSource) Memberships(ctx context.Context, principalID uuid.UUID, limit int, cursor string) ([]OrgClaim, string, error) {
	if limit <= 0 {
		limit = DefaultMembershipsPageSize
	}
	if limit > MaxMembershipsPageSize {
		limit = MaxMembershipsPageSize
	}
	list, err := s.entries(ctx, principalID)
	if err != nil {
		return nil, "", err
	}
	start := 0
	if cursor != "" {
		after, err := uuid.Parse(cursor)
		if err != nil {
			return nil, "", ErrInvalidCursor
		}
		found := false
		for i, e := range list {
			if e.org.ID == after {
				start, found = i+1, true
				break
			}
		}
		if !found {
			return nil, "", ErrInvalidCursor
		}
	}
	end := start + limit
	next := ""
	if end < len(list) {
		next = list[end-1].org.ID.String()
	} else {
		end = len(list)
	}
	page := make([]OrgClaim, 0, end-start)
	for _, e := range list[start:end] {
		c, err := s.claim(ctx, principalID, e, false)
		if err != nil {
			return nil, "", err
		}
		page = append(page, c)
	}
	return page, next, nil
}

// WithOrgsSource makes the server emit the orgs claim (ADR-007) in ID
// tokens, at the userinfo endpoint and, in compact form, in JWT access
// tokens, and serve GET /oauth/userinfo/memberships. Without it no
// organization claim is emitted.
func WithOrgsSource(src OrgsSource) Option {
	return func(s *Server) { s.orgs = src }
}

// OrgsClaim returns the principal's orgs claim, compact for access
// tokens. It returns an empty result when no OrgsSource is configured.
func (s *Server) OrgsClaim(ctx context.Context, principalID uuid.UUID, compact bool) (OrgsResult, error) {
	if s.orgs == nil {
		return OrgsResult{Orgs: []OrgClaim{}}, nil
	}
	return s.orgs.OrgsClaim(ctx, principalID, compact)
}

// principalSubject parses a token subject as a principal ID. Subjects
// that are not (a client's own ID under client_credentials) have no
// organizations.
func principalSubject(subject string) (uuid.UUID, bool) {
	id, err := uuid.Parse(subject)
	return id, err == nil && id != uuid.Nil
}

// addOrgsClaims adds the orgs claim to claims, whatever the scopes: it is
// authorization data, like managed. It returns claims unchanged for a
// subject that is not a principal or with no OrgsSource.
func (s *Server) addOrgsClaims(ctx context.Context, subject string, claims map[string]any, compact bool) (map[string]any, error) {
	if s.orgs == nil {
		return claims, nil
	}
	id, ok := principalSubject(subject)
	if !ok {
		return claims, nil
	}
	res, err := s.OrgsClaim(ctx, id, compact)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(claims)+2)
	for k, v := range claims {
		out[k] = v
	}
	out[OrgsClaim] = res.Orgs
	out[OrgsTruncatedClaim] = res.Truncated
	return out, nil
}

// MembershipsResponse is the body of GET /oauth/userinfo/memberships.
type MembershipsResponse struct {
	Orgs       []OrgClaim `json:"orgs"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

// membershipsEndpoint serves GET /oauth/userinfo/memberships?limit=&cursor=.
func (s *Server) membershipsEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)

	token := bearerToken(r)
	if token == "" {
		writeBearerError(w, http.StatusUnauthorized, "", "", "")
		return
	}
	ar, err := s.introspect(ctx, token, fosite.AccessToken, s.Session(""))
	if err != nil {
		logger.Debug("memberships: invalid access token", "error", err)
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "The access token is invalid, expired or revoked.", "")
		return
	}
	subject := sessionSubject(ar.GetSession())
	principalID, isPrincipal := principalSubject(subject)
	if !ar.GetGrantedScopes().Has("openid") || !isPrincipal {
		writeBearerError(w, http.StatusForbidden, "insufficient_scope", "The access token was not granted the openid scope.", "openid")
		return
	}
	if s.orgs == nil {
		http.Error(w, "memberships are not configured", http.StatusNotImplemented)
		return
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
			return
		}
		limit = n
	}
	page, next, err := s.orgs.Memberships(ctx, principalID, limit, r.URL.Query().Get("cursor"))
	if errors.Is(err, ErrInvalidCursor) {
		http.Error(w, "invalid cursor", http.StatusBadRequest)
		return
	}
	if err != nil {
		logger.Error("memberships: reading memberships", "error", err)
		http.Error(w, "could not read memberships", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(MembershipsResponse{Orgs: page, NextCursor: next}); err != nil {
		logger.Error("writing memberships response", "error", err)
	}
}

// MembershipsInput documents the memberships request for OpenAPI.
type MembershipsInput struct {
	Authorization string `header:"Authorization" doc:"Bearer access token granted the openid scope"`
	Limit         int    `query:"limit" minimum:"1" maximum:"100" doc:"Page size (default 50)"`
	Cursor        string `query:"cursor" doc:"next_cursor of the previous page"`
}

// MembershipsOutput documents the memberships response for OpenAPI.
type MembershipsOutput struct {
	Body MembershipsResponse
}

// registerMembershipsOperation documents /oauth/userinfo/memberships. The
// handler itself is served by fositeInterceptor.
func (s *Server) registerMembershipsOperation() {
	huma.Register(s.huma, huma.Operation{
		OperationID: "userinfo-memberships",
		Method:      http.MethodGet,
		Path:        MembershipsPath,
		Summary:     "Organization memberships of the token's principal",
		Description: "Returns every organization the principal belongs to, in the full form of the orgs claim (id, slug, name, type, role, apps), personal organization first and then newest membership first, paginated by next_cursor. Tokens and userinfo carry at most 50; use this to read the rest.",
		Tags:        []string{"OpenID Connect"},
	}, func(_ context.Context, _ *MembershipsInput) (*MembershipsOutput, error) {
		return &MembershipsOutput{}, nil
	})
}
