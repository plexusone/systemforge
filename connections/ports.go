package connections

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	cf "github.com/plexusone/connectforge"
	"github.com/plexusone/keyforge"
	"github.com/plexusone/omnivault/vault"

	"github.com/plexusone/systemforge/authz"
	sfaudit "github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/keys"
)

// cryptographer seals credentials with the keys package.
type cryptographer struct{ k *keys.Keys }

func (c cryptographer) Seal(ctx context.Context, purpose string, plaintext, aad []byte) ([]byte, error) {
	return c.k.Seal(ctx, keyforge.Purpose(purpose), plaintext, aad)
}

func (c cryptographer) Open(ctx context.Context, purpose string, ciphertext, aad []byte) ([]byte, error) {
	return c.k.Open(ctx, keyforge.Purpose(purpose), ciphertext, aad)
}

// ErrNoVault is returned when a deployment secret is read and no vault was
// configured.
var ErrNoVault = errors.New("connections: no vault configured")

// secretSource reads deployment secrets from omnivault.
type secretSource struct{ v vault.Vault }

func (s secretSource) Secret(ctx context.Context, ref string) (cf.Secret, error) {
	if s.v == nil {
		return cf.Secret{}, ErrNoVault
	}
	sec, err := s.v.Get(ctx, ref)
	if err != nil {
		// omnivault errors name the path, never the value.
		return cf.Secret{}, fmt.Errorf("connections: deployment secret %s: %w", ref, err)
	}
	return cf.NewSecret(sec.Bytes()), nil
}

// ResourceType is the authorization resource type of a connection. It follows
// the "{app}_{type}" naming of resource-scoped grants (ADR-008).
const ResourceType authz.ResourceType = "systemforge_connection"

// PrincipalTypeAgent is the authorization principal type for an agent.
const PrincipalTypeAgent authz.PrincipalType = "agent"

// permission maps a connection action onto the resource permission ladder of
// ADR-008: viewers view, contributors also use, maintainers (and organization
// owners and admins) also manage, share and disconnect.
func permission(a cf.Action) (authz.Action, bool) {
	switch a {
	case cf.ActionView:
		return authz.PermResourceView, true
	case cf.ActionUse:
		return authz.PermResourceEdit, true
	case cf.ActionManage, cf.ActionShare, cf.ActionDisconnect:
		return authz.PermResourceManage, true
	}
	return "", false
}

// RolePermissions returns base with the organization roles' permissions on
// connections added: owners and admins view, use and manage them; members
// view them. Use it with the role-based provider (rbac.WithPermissions).
func RolePermissions(base authz.RolePermissions) authz.RolePermissions {
	out := make(authz.RolePermissions, len(base))
	for role, perms := range base {
		out[role] = append([]string(nil), perms...)
	}
	perm := func(a authz.Action) string { return string(ResourceType) + "." + string(a) }
	all := []string{perm(authz.PermResourceView), perm(authz.PermResourceEdit), perm(authz.PermResourceManage)}
	out["owner"] = append(out["owner"], all...)
	out["admin"] = append(out["admin"], all...)
	out["member"] = append(out["member"], perm(authz.PermResourceView))
	return out
}

func principalType(k cf.PrincipalKind) authz.PrincipalType {
	switch k {
	case cf.PrincipalService:
		return authz.PrincipalTypeService
	case cf.PrincipalAgent:
		return PrincipalTypeAgent
	}
	return authz.PrincipalTypeUser
}

// authorizer asks the platform's authorization about a connection.
type authorizer struct{ az authz.Authorizer }

func (a authorizer) Allowed(ctx context.Context, p cf.Principal, act cf.Action, c cf.Connection) error {
	perm, ok := permission(act)
	if !ok {
		return fmt.Errorf("%w: unknown action %q", cf.ErrDenied, act)
	}
	pid, err := uuid.Parse(p.ID)
	if err != nil {
		return fmt.Errorf("%w: principal is not a platform identifier", cf.ErrDenied)
	}
	cid, err := uuid.Parse(c.ID)
	if err != nil {
		return fmt.Errorf("%w: connection is not a platform identifier", cf.ErrDenied)
	}
	org, err := uuid.Parse(string(c.Owner))
	if err != nil {
		return fmt.Errorf("%w: owner is not an organization", cf.ErrDenied)
	}
	res := authz.Resource{Type: ResourceType, ID: &cid, OrgID: &org}
	principal := authz.Principal{ID: pid, Type: principalType(p.Kind)}
	// The principal who created a stored connection manages it (ADR-017),
	// while still a member of the owning organization: a creator who left or
	// was removed keeps nothing. A connection not yet stored has no owner,
	// so creating one is decided by the organization role alone.
	if creator, err := uuid.Parse(c.CreatedBy.ID); err == nil && c.Revision > 0 && c.CreatedBy.Kind == cf.PrincipalUser {
		member, err := a.isMember(ctx, principal, creator, org)
		if err != nil {
			return fmt.Errorf("connections: authorization: %w", err)
		}
		if member {
			res.OwnerID = &creator
		}
	}
	allowed, err := a.az.Can(ctx, principal, perm, res)
	if err != nil {
		return fmt.Errorf("connections: authorization: %w", err)
	}
	if !allowed {
		return fmt.Errorf("%w: %s on connection %s", cf.ErrDenied, act, c.ID)
	}
	return nil
}

// isMember reports whether the creator is the requesting principal and a
// member (collaborators included) of org. An Authorizer that cannot answer
// membership (not an authz.OrgAuthorizer) grants no creator rights.
func (a authorizer) isMember(ctx context.Context, principal authz.Principal, creator, org uuid.UUID) (bool, error) {
	if creator != principal.ID {
		// Ownership only matters to the creator; anyone else is decided by
		// role and grants.
		return false, nil
	}
	oa, ok := a.az.(authz.OrgAuthorizer)
	if !ok {
		return false, nil
	}
	return oa.IsMember(ctx, principal, org)
}

// auditor records connection events in the platform audit trail.
type auditor struct{ store sfaudit.Store }

func (a auditor) Record(ctx context.Context, e cf.Event) error {
	ev := &sfaudit.Event{
		Timestamp: e.Time,
		EventType: "connections",
		Action:    string(e.Type),
		Actor:     sfaudit.Actor{Type: string(e.Actor.Kind), Identifier: e.Actor.ID},
		Resource:  sfaudit.Resource{Type: string(ResourceType), Identifier: e.ConnectionID},
		Outcome:   "failure",
		Details:   map[string]any{},
	}
	if e.Success {
		ev.Outcome = "success"
	}
	if id, err := uuid.Parse(e.Actor.ID); err == nil {
		ev.Actor.ID = id
	}
	if id, err := uuid.Parse(e.ConnectionID); err == nil {
		ev.Resource.ID = id
	}
	if org, err := uuid.Parse(string(e.Owner)); err == nil {
		ev.Context.TenantID = &org
	}
	if e.Provider != "" {
		ev.Details["provider"] = e.Provider
	}
	if e.Reason != "" {
		ev.Details["reason"] = e.Reason
	}
	if e.OnBehalfOf != nil {
		ev.Details["on_behalf_of"] = string(e.OnBehalfOf.Kind) + ":" + e.OnBehalfOf.ID
	}
	for k, v := range e.Details {
		ev.Details[k] = v
	}
	if _, err := a.store.Record(ctx, ev); err != nil {
		return fmt.Errorf("connections: recording %s: %w", e.Type, err)
	}
	return nil
}

// nopAuditor is used when no audit store is configured.
type nopAuditor struct{}

func (nopAuditor) Record(context.Context, cf.Event) error { return nil }

// LogAuditor returns an auditor that writes connection events as structured
// log records, for a deployment without an audit store.
func LogAuditor(logger *slog.Logger) cf.Auditor { return logAuditor{log: logger} }

type logAuditor struct{ log *slog.Logger }

func (a logAuditor) Record(ctx context.Context, e cf.Event) error {
	attrs := []any{
		"event", string(e.Type), "success", e.Success, "owner", string(e.Owner),
		"actor", string(e.Actor.Kind) + ":" + e.Actor.ID, "connection", e.ConnectionID, "provider", e.Provider,
	}
	if e.Reason != "" {
		attrs = append(attrs, "reason", e.Reason)
	}
	a.log.InfoContext(ctx, "connections audit", attrs...)
	return nil
}
