package relyingparty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
)

// ClaimsMemberships reads memberships from the SystemAuth "orgs" claim of
// the verified claims (ADR-007): the ID token and userinfo claims of a BFF
// session, or the claims of a JWT access token. It is the default source.
//
// The claim lists the principal's organizations with their role and, in
// "apps", the principal's role in each application. A JWT access token
// carries the compact form without slug, name or type. When the server
// omitted organizations ("orgs_truncated") or the application needs more
// than the token carries, wrap this source with ClaimsOrRemoteMemberships.
//
// A request without claims, such as one authenticated by an API key, has no
// memberships from this source.
var ClaimsMemberships MembershipSource = MembershipSourceFunc(func(_ context.Context, q MembershipQuery) ([]Membership, error) {
	return MembershipsFromClaims(q.Claims), nil
})

// MembershipsFromClaims decodes the "orgs" claim. Entries that are not
// objects with an "id" are skipped.
func MembershipsFromClaims(claims map[string]any) []Membership {
	orgs, _ := claims["orgs"].([]any)
	if orgs == nil {
		if typed, ok := claims["orgs"].([]map[string]any); ok {
			orgs = make([]any, len(typed))
			for i, o := range typed {
				orgs[i] = o
			}
		}
	}
	return decodeOrgs(orgs)
}

// OrgsTruncated reports whether the claims say SystemAuth omitted
// organizations from "orgs".
func OrgsTruncated(claims map[string]any) bool {
	t, _ := claims["orgs_truncated"].(bool)
	return t
}

func decodeOrgs(orgs []any) []Membership {
	out := make([]Membership, 0, len(orgs))
	for _, o := range orgs {
		m, ok := o.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		if id == "" {
			continue
		}
		mem := Membership{ID: id, OrganizationID: id}
		mem.OrganizationSlug, _ = m["slug"].(string)
		mem.OrganizationName, _ = m["name"].(string)
		mem.OrganizationType, _ = m["type"].(string)
		mem.Role, _ = m["role"].(string)
		mem.Applications = decodeApps(m["apps"])
		out = append(out, mem)
	}
	return out
}

func decodeApps(v any) map[string]string {
	apps, ok := v.(map[string]any)
	if !ok {
		if typed, isTyped := v.(map[string]string); isTyped {
			return typed
		}
		return nil
	}
	out := make(map[string]string, len(apps))
	for app, role := range apps {
		if r, ok := role.(string); ok {
			out[app] = r
		}
	}
	return out
}

// maxRemotePages bounds RemoteMemberships' paging so a misbehaving server
// cannot make a request loop.
const maxRemotePages = 50

// memberships page size asked of SystemAuth (its maximum).
const remotePageSize = 100

// RemoteMemberships reads the full membership list from SystemAuth's
// memberships endpoint (GET <userinfo endpoint>/memberships), following the
// pagination cursor. It needs an access token granted openid, which a JWT
// access token or a BFF session supplies; a request without one (an API
// key) has no memberships from this source.
//
// Use it when the claims cannot answer: the token was truncated, or the
// application holds only the compact access-token form and needs slugs and
// names. ClaimsOrRemoteMemberships does that choice for you.
func RemoteMemberships(c *Client) MembershipSource {
	return MembershipSourceFunc(func(ctx context.Context, q MembershipQuery) ([]Membership, error) {
		if q.AccessToken == nil {
			return nil, nil
		}
		token, err := q.AccessToken(ctx)
		if err != nil {
			return nil, err
		}
		return c.fetchMemberships(ctx, token)
	})
}

// ClaimsOrRemoteMemberships reads the claims and falls back to remote when
// they cannot answer: when SystemAuth truncated "orgs" or when the claims
// carry none (a compact token without the claim, or a server without an
// OrgsSource). If remote fails, the claims' possibly partial answer is
// returned and the failure logged, so SystemAuth being unavailable does not
// stop requests (ADR-007: serve from the last token).
func ClaimsOrRemoteMemberships(remote MembershipSource, logger *slog.Logger) MembershipSource {
	if logger == nil {
		logger = slog.Default()
	}
	return MembershipSourceFunc(func(ctx context.Context, q MembershipQuery) ([]Membership, error) {
		_, hasOrgs := q.Claims["orgs"]
		fromClaims := MembershipsFromClaims(q.Claims)
		if hasOrgs && !OrgsTruncated(q.Claims) {
			return fromClaims, nil
		}
		full, err := remote.Memberships(ctx, q)
		if err != nil {
			logger.WarnContext(ctx, "reading memberships from SystemAuth failed; using token claims", "error", err)
			return fromClaims, nil
		}
		if full == nil && len(fromClaims) > 0 {
			return fromClaims, nil
		}
		return full, nil
	})
}

// membershipsEndpoint is the memberships endpoint derived from the
// advertised userinfo endpoint.
func (c *Client) membershipsEndpoint() (string, error) {
	ep := c.metadata.UserinfoEndpoint
	if ep == "" {
		return "", errors.New("relyingparty: SystemAuth advertises no userinfo endpoint")
	}
	return ep + "/memberships", nil
}

func (c *Client) fetchMemberships(ctx context.Context, accessToken string) ([]Membership, error) {
	endpoint, err := c.membershipsEndpoint()
	if err != nil {
		return nil, err
	}
	var out []Membership
	cursor := ""
	for range maxRemotePages {
		page, next, err := c.membershipsPage(ctx, endpoint, accessToken, cursor)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if next == "" {
			return out, nil
		}
		cursor = next
	}
	return nil, fmt.Errorf("relyingparty: memberships: more than %d pages", maxRemotePages)
}

func (c *Client) membershipsPage(ctx context.Context, endpoint, accessToken, cursor string) (page []Membership, next string, err error) {
	q := url.Values{"limit": {strconv.Itoa(remotePageSize)}}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), http.NoBody)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("relyingparty: memberships: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("relyingparty: memberships: status %d (%s)", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentSize))
	if err != nil {
		return nil, "", fmt.Errorf("relyingparty: memberships: reading: %w", err)
	}
	var doc struct {
		Orgs       []any  `json:"orgs"`
		NextCursor string `json:"next_cursor"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("relyingparty: memberships: decoding: %w", err)
	}
	return decodeOrgs(doc.Orgs), doc.NextCursor, nil
}

// ProvisioningMemberships wraps src so that the first time a principal
// holding a role in application is seen in an organization, provision runs
// for that organization (ADR-007 decision 10): the application creates its
// own records for an organization ID on first use instead of keeping
// membership tables. provision receives the membership, whose
// OrganizationID is the SystemAuth organization ID to key data by.
//
// provision must be idempotent: it runs once per organization per process,
// so other instances and restarts run it again. A failure is returned from
// Memberships (the request fails) and the organization is retried on the
// next request. Organizations in which the principal holds no role in
// application are not provisioned.
func ProvisioningMemberships(src MembershipSource, application string, provision func(ctx context.Context, m Membership) error) MembershipSource {
	var mu sync.Mutex
	done := map[string]bool{}
	return MembershipSourceFunc(func(ctx context.Context, q MembershipQuery) ([]Membership, error) {
		ms, err := src.Memberships(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			if m.Applications[application] == "" {
				continue
			}
			// Held across provision so concurrent first requests for one
			// organization run it once.
			mu.Lock()
			if done[m.OrganizationID] {
				mu.Unlock()
				continue
			}
			err := provision(ctx, m)
			if err == nil {
				done[m.OrganizationID] = true
			}
			mu.Unlock()
			if err != nil {
				return nil, fmt.Errorf("relyingparty: provisioning organization %s: %w", m.OrganizationID, err)
			}
		}
		return ms, nil
	})
}
