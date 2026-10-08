package marketplace

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// ErrNoCaller is returned when a request carries no authenticated
// principal that the marketplace can act for.
var ErrNoCaller = errors.New("marketplace: no authenticated caller")

// CallerResolver returns the principal making a request. It returns
// ErrNoCaller when the request is unauthenticated.
type CallerResolver func(ctx context.Context) (uuid.UUID, error)

// RequestPrincipalCaller resolves the caller from requestprincipal, as set
// by requestprincipal.Middleware. Principals whose ID is not a SystemForge
// principal ID, such as issuer-qualified subjects of credentials issued
// elsewhere, cannot act in the marketplace.
func RequestPrincipalCaller(ctx context.Context) (uuid.UUID, error) {
	rp, ok := requestprincipal.FromContext(ctx)
	if !ok {
		return uuid.Nil, ErrNoCaller
	}
	id, err := uuid.Parse(rp.PrincipalID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: principal %q is not a SystemForge principal", ErrNoCaller, rp.PrincipalID)
	}
	return id, nil
}

// PurchaseAuthorizer decides whether a principal may buy on behalf of an
// organization.
type PurchaseAuthorizer interface {
	CanPurchase(ctx context.Context, principalID, orgID uuid.UUID) (bool, error)
}

// PurchaseAuthorizerFunc adapts a function to PurchaseAuthorizer.
type PurchaseAuthorizerFunc func(ctx context.Context, principalID, orgID uuid.UUID) (bool, error)

// CanPurchase implements PurchaseAuthorizer.
func (f PurchaseAuthorizerFunc) CanPurchase(ctx context.Context, principalID, orgID uuid.UUID) (bool, error) {
	return f(ctx, principalID, orgID)
}

// DefaultPurchaseRoles are the organization roles that may buy for it:
// the roles that manage the organization.
var DefaultPurchaseRoles = []string{"owner", "admin"}

// OrgRolePurchaseAuthorizer allows purchases by principals holding one of
// roles in the organization, DefaultPurchaseRoles when none are given. It
// uses the organization role, which both authorization providers report
// the same way.
func OrgRolePurchaseAuthorizer(orgs authz.OrgAuthorizer, roles ...string) PurchaseAuthorizer {
	if len(roles) == 0 {
		roles = DefaultPurchaseRoles
	}
	return PurchaseAuthorizerFunc(func(ctx context.Context, principalID, orgID uuid.UUID) (bool, error) {
		role, err := orgs.GetRole(ctx, authz.NewUserPrincipal(principalID), orgID)
		if err != nil {
			return false, fmt.Errorf("marketplace: organization role: %w", err)
		}
		return slices.Contains(roles, role), nil
	})
}

// APIOption configures an API.
type APIOption func(*API)

// WithCallerResolver sets how the API identifies the calling principal.
// Defaults to RequestPrincipalCaller.
func WithCallerResolver(r CallerResolver) APIOption {
	return func(a *API) { a.caller = r }
}

// WithPurchaseAuthorizer sets who may buy for an organization. Checkout
// is refused until one is configured, for example
// OrgRolePurchaseAuthorizer(orgAuthorizer).
func WithPurchaseAuthorizer(p PurchaseAuthorizer) APIOption {
	return func(a *API) { a.purchases = p }
}
