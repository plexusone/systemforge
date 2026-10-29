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

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	orgsvc "github.com/plexusone/systemforge/identity/organization"
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
	// ResolveMembershipPath resolves an organization slug, current or
	// given up within the cooling-off period, among the token principal's
	// memberships.
	ResolveMembershipPath = MembershipsPath + "/resolve"

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

// MembershipResolver is implemented by an OrgsSource that can resolve an
// organization slug among a principal's memberships. EntOrgsSource
// implements it; without it, ResolveMembershipPath answers 501.
type MembershipResolver interface {
	// ResolveMembership returns, in the full form, the organization slug
	// names, when principalID is an active member of it. alias is true
	// when slug is one the organization gave up within the cooling-off
	// period (Slug is then the current slug). It returns
	// ErrMembershipNotResolved when no such organization exists or the
	// principal is not a member, without saying which.
	ResolveMembership(ctx context.Context, principalID uuid.UUID, slug string) (org OrgClaim, alias bool, err error)
}

// ErrMembershipNotResolved means a slug names no organization the
// principal is an active member of.
var ErrMembershipNotResolved = errors.New("systemauth: no membership in an organization with that slug")

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

// ResolveMembership implements MembershipResolver: slug resolves as
// organization.Service ResolveSlug does (a renamed organization's old slug
// keeps working during its cooling-off period).
func (s *EntOrgsSource) ResolveMembership(ctx context.Context, principalID uuid.UUID, slug string) (OrgClaim, bool, error) {
	if slug == "" || len(slug) > maxSlugLength {
		return OrgClaim{}, false, ErrMembershipNotResolved
	}
	org, alias, err := orgsvc.NewService(s.client).ResolveSlug(ctx, slug)
	if errors.Is(err, orgsvc.ErrOrganizationNotFound) {
		return OrgClaim{}, false, ErrMembershipNotResolved
	}
	if err != nil {
		return OrgClaim{}, false, fmt.Errorf("systemauth: resolving slug: %w", err)
	}
	m, err := s.client.PrincipalMembership.Query().
		Where(
			principalmembership.PrincipalID(principalID),
			principalmembership.OrganizationID(org.ID),
			principalmembership.Active(true),
		).
		WithOrganization().
		Only(ctx)
	if ent.IsNotFound(err) {
		return OrgClaim{}, false, ErrMembershipNotResolved
	}
	if err != nil {
		return OrgClaim{}, false, fmt.Errorf("systemauth: reading membership: %w", err)
	}
	if m.Edges.Organization == nil {
		return OrgClaim{}, false, ErrMembershipNotResolved
	}
	c, err := s.claim(ctx, principalID, orgEntry{membershipID: m.ID, createdAt: m.CreatedAt, org: m.Edges.Organization, role: m.Role}, false)
	if err != nil {
		return OrgClaim{}, false, err
	}
	return c, alias, nil
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

// maxSlugLength bounds the slug a resolve request may name.
const maxSlugLength = 255

// membershipsCaller authenticates a memberships request: an access token
// granted openid, naming a principal. It writes the error response and
// returns false when the request is refused.
func (s *Server) membershipsCaller(w http.ResponseWriter, r *http.Request, path string) (uuid.UUID, bool) {
	ar, authErr := s.authenticateAccessToken(r, s.endpointURL(path))
	if authErr != nil {
		LoggerFromContext(r.Context()).Debug("memberships: access token refused", "error", authErr)
		s.writeTokenAuthError(w, authErr)
		return uuid.Nil, false
	}
	subject := sessionSubject(ar.GetSession())
	principalID, isPrincipal := principalSubject(subject)
	if !ar.GetGrantedScopes().Has("openid") || !isPrincipal {
		writeScopeError(w, ar, "The access token was not granted the openid scope.", "openid")
		return uuid.Nil, false
	}
	return principalID, true
}

// membershipsEndpoint serves GET /oauth/userinfo/memberships?limit=&cursor=.
func (s *Server) membershipsEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)

	principalID, ok := s.membershipsCaller(w, r, MembershipsPath)
	if !ok {
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

// ResolveMembershipResponse is the body of GET
// /oauth/userinfo/memberships/resolve.
type ResolveMembershipResponse struct {
	// Org is the organization in the full form of the orgs claim, with its
	// current slug.
	Org OrgClaim `json:"org"`
	// Alias is true when the requested slug is one the organization gave
	// up within the cooling-off period; update stored links to Org.Slug.
	Alias bool `json:"alias"`
}

// resolveMembershipEndpoint serves GET
// /oauth/userinfo/memberships/resolve?slug=. A slug that names no
// organization and one the principal is not a member of both answer 404,
// so the endpoint does not reveal other organizations.
func (s *Server) resolveMembershipEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)

	principalID, ok := s.membershipsCaller(w, r, ResolveMembershipPath)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	resolver, ok := s.orgs.(MembershipResolver)
	if !ok {
		http.Error(w, "membership resolution is not configured", http.StatusNotImplemented)
		return
	}
	slug := r.URL.Query().Get("slug")
	if slug == "" {
		http.Error(w, "slug is required", http.StatusBadRequest)
		return
	}
	org, alias, err := resolver.ResolveMembership(ctx, principalID, slug)
	if errors.Is(err, ErrMembershipNotResolved) {
		http.Error(w, "organization not found", http.StatusNotFound)
		return
	}
	if err != nil {
		logger.Error("memberships: resolving slug", "error", err)
		http.Error(w, "could not resolve the organization", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ResolveMembershipResponse{Org: org, Alias: alias}); err != nil {
		logger.Error("writing membership resolution", "error", err)
	}
}

// ResolveMembershipInput documents the resolve request for OpenAPI.
type ResolveMembershipInput struct {
	Authorization string `header:"Authorization" doc:"Bearer access token granted the openid scope"`
	Slug          string `query:"slug" required:"true" doc:"Organization slug, current or given up within the cooling-off period"`
}

// ResolveMembershipOutput documents the resolve response for OpenAPI.
type ResolveMembershipOutput struct {
	Body ResolveMembershipResponse
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
	huma.Register(s.huma, huma.Operation{
		OperationID: "userinfo-memberships-resolve",
		Method:      http.MethodGet,
		Path:        ResolveMembershipPath,
		Summary:     "Resolve an organization slug among the token principal's memberships",
		Description: "Returns the organization a slug names, in the full form of the orgs claim with its current slug, when the token's principal is an active member of it. A slug the organization gave up by renaming keeps resolving during its cooling-off period, with alias true. An unknown slug and an organization the principal does not belong to both answer 404.",
		Tags:        []string{"OpenID Connect"},
	}, func(_ context.Context, _ *ResolveMembershipInput) (*ResolveMembershipOutput, error) {
		return &ResolveMembershipOutput{}, nil
	})
}
