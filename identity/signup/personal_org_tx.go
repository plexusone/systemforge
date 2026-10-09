package signup

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	entorg "github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/slugreservation"
	"github.com/plexusone/systemforge/identity/organization"
)

// PersonalOrgParams describes a personal organization to create inside a
// caller-provided transaction.
type PersonalOrgParams struct {
	// OwnerID is the owning principal; it becomes the active owner member.
	OwnerID uuid.UUID
	// Name is the organization's display name (required).
	Name string
	// Slug is the preferred slug. It is made valid and, when taken, given a
	// numeric suffix. Use SlugForLogin to derive it.
	Slug string
	// ReservedSlugs are deployment-configured slugs to avoid in addition to
	// organization.ReservedSlugs; a reserved slug gets a numeric suffix.
	ReservedSlugs []string
	// LogoURL is the optional logo, usually the owner's avatar.
	LogoURL string
}

// PersonalOrg is a personal organization and its owner membership.
type PersonalOrg struct {
	Organization *ent.Organization
	Membership   *ent.PrincipalMembership
}

// CreatePersonalOrgInTx creates a personal organization with an active
// owner membership inside tx, so a caller can make it atomic with the
// principal it belongs to. The caller commits or rolls back. It does not
// notify an authorization syncer: services that need that call
// organization.Service.CreatePersonalOrg instead.
//
// The organization has type personal. Its
// slug is params.Slug if free, else params.Slug-1 ... -100, else the slug
// with an eight-character random suffix. Two transactions may still pick
// the same free slug; the loser fails with a constraint error and the
// caller retries the whole transaction.
func CreatePersonalOrgInTx(ctx context.Context, tx *ent.Tx, params PersonalOrgParams) (*PersonalOrg, error) {
	if params.OwnerID == uuid.Nil {
		return nil, fmt.Errorf("signup: personal organization requires an owner")
	}
	if params.Name == "" {
		return nil, fmt.Errorf("signup: personal organization requires a name")
	}
	slug, err := uniqueSlugInTx(ctx, tx, normalizeSlug(params.Slug), params.ReservedSlugs...)
	if err != nil {
		return nil, err
	}
	oc := tx.Organization.Create().
		SetName(params.Name).
		SetSlug(slug).
		SetOrgType(entorg.OrgTypePersonal).
		SetOwnerPrincipalID(params.OwnerID).
		SetActive(true)
	if params.LogoURL != "" {
		oc.SetLogoURL(params.LogoURL)
	}
	org, err := oc.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating personal organization: %w", err)
	}
	m, err := tx.PrincipalMembership.Create().
		SetPrincipalID(params.OwnerID).
		SetOrganizationID(org.ID).
		SetRole(organization.RoleOwner).
		SetActive(true).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating owner membership: %w", err)
	}
	return &PersonalOrg{Organization: org, Membership: m}, nil
}

// EnsurePersonalOrgInTx creates the principal's personal organization when
// it has none, and reports whether it did. It is the idempotent backfill for
// a principal that predates signup-on-first-login, and it is safe to call on
// every login: an existing personal organization is returned untouched.
//
// The principal row is locked so two concurrent logins of the same existing
// principal do not both create an organization.
func EnsurePersonalOrgInTx(ctx context.Context, tx *ent.Tx, params PersonalOrgParams) (*PersonalOrg, bool, error) {
	// Touching the principal row takes its row lock until the transaction
	// ends, serializing concurrent backfills for the same principal.
	if _, err := tx.Principal.UpdateOneID(params.OwnerID).Save(ctx); err != nil {
		return nil, false, fmt.Errorf("locking principal: %w", err)
	}
	existing, err := tx.Organization.Query().
		Where(entorg.OwnerPrincipalIDEQ(params.OwnerID), entorg.OrgTypeEQ(entorg.OrgTypePersonal)).
		First(ctx)
	switch {
	case err == nil:
		return &PersonalOrg{Organization: existing}, false, nil
	case !ent.IsNotFound(err):
		return nil, false, fmt.Errorf("finding personal organization: %w", err)
	}
	po, err := CreatePersonalOrgInTx(ctx, tx, params)
	if err != nil {
		return nil, false, err
	}
	return po, true, nil
}

// uniqueSlugInTx returns base, or base with a numeric suffix, that no
// organization uses, that is not reserved (the built-in list plus extra) and
// that is not in the cooling-off period after a rename.
// base must be valid.
func uniqueSlugInTx(ctx context.Context, tx *ent.Tx, base string, extra ...string) (string, error) {
	reserved := make(map[string]struct{}, len(extra))
	for _, r := range extra {
		reserved[strings.ToLower(r)] = struct{}{}
	}
	candidates := []string{base}
	for i := 1; i <= 100; i++ {
		candidates = append(candidates, withSuffix(base, fmt.Sprintf("-%d", i)))
	}
	candidates = append(candidates, withSuffix(base, "-"+uuid.NewString()[:8]))
	for _, c := range candidates {
		if _, ok := reserved[c]; ok || organization.IsReservedSlug(c) {
			continue
		}
		taken, err := tx.Organization.Query().Where(entorg.SlugEQ(c)).Exist(ctx)
		if err != nil {
			return "", fmt.Errorf("checking slug: %w", err)
		}
		if taken {
			continue
		}
		// A slug an organization just gave up is held for whoever released
		// it; a new account does not get it.
		held, err := tx.SlugReservation.Query().
			Where(slugreservation.SlugEQ(c), slugreservation.ExpiresAtGT(time.Now())).
			Exist(ctx)
		if err != nil {
			return "", fmt.Errorf("checking slug reservation: %w", err)
		}
		if !held {
			return c, nil
		}
	}
	return "", fmt.Errorf("signup: no free slug for %q", base)
}

// withSuffix appends suffix to base, shortening base so the slug stays
// within 63 characters and does not end in a hyphen before the suffix.
func withSuffix(base, suffix string) string {
	const maxLen = 63
	if len(base)+len(suffix) > maxLen {
		base = base[:maxLen-len(suffix)]
		for len(base) > 0 && base[len(base)-1] == '-' {
			base = base[:len(base)-1]
		}
	}
	return base + suffix
}
