package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemspec-pricingpackaging/pricingspec"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/marketplace"
)

// ConsolePath is the organization's billing in the console's API, relative
// to the console's prefix. The checkout and portal endpoints are under it.
const ConsolePath = "/api/v1/organizations/{org}/billing"

// OrganizationPlan is the plan an organization is on: the plan the
// operator set, when there is one (ADR-022); otherwise its platform
// subscription's plan while the subscription grants it (active, in a
// trial, or past due); and the spec's default plan otherwise. payments is
// whether the deployment takes payments; in free mode it does not, and a
// paid subscription grants nothing, so a deployment that removes its key
// puts every organization without an operator's plan on the default plan.
// The subscription is returned either way, and is nil when the
// organization never had one.
func OrganizationPlan(ctx context.Context, db *ent.Client, spec *pricingspec.Spec, org uuid.UUID, payments bool) (pricingspec.Plan, *marketplace.Subscription, error) {
	sub, err := marketplace.NewEntSubscriptionService(db).GetByOrg(ctx, org)
	if errors.Is(err, marketplace.ErrSubscriptionNotFound) {
		return spec.PlanOrDefault(""), nil, nil
	}
	if err != nil {
		return pricingspec.Plan{}, nil, fmt.Errorf("billing: organization plan: %w", err)
	}
	if sub.OperatorPlan != "" {
		return spec.PlanOrDefault(sub.OperatorPlan), sub, nil
	}
	plan, ok := sub.GrantedPlan()
	if !payments || !ok {
		return spec.PlanOrDefault(""), sub, nil
	}
	return spec.PlanOrDefault(plan), sub, nil
}

// ConsoleConfig configures the console's billing section.
type ConsoleConfig struct {
	Spec *pricingspec.Spec
	DB   *ent.Client
	// Checkout takes payment. Nil is free mode: the section shows the
	// default plan and refuses checkout. Its Caller, Organization and
	// Purchases are set by NewConsole.
	Checkout *CheckoutConfig
	// Mode is the payment provider's mode, "test" or "live", shown so a
	// test deployment is never mistaken for a live one.
	Mode string
	// Principal returns the person signed in on r. Required.
	Principal func(r *http.Request) (uuid.UUID, error)
	// WriteAuthError answers a request whose Principal failed. Required.
	WriteAuthError func(w http.ResponseWriter, err error)
	// Role returns the person's organization role, or "" when they are not
	// a member. Required.
	Role func(ctx context.Context, principal, org uuid.UUID) (string, error)
	// ManageRoles may choose a plan and open the billing portal. Default
	// marketplace.DefaultPurchaseRoles (owner and admin). Every member may
	// see the plan.
	ManageRoles []string
	Logger      *slog.Logger
}

// Status is an organization's billing as the console shows it.
type Status struct {
	// Configured is false in free mode.
	Configured bool   `json:"configured"`
	Mode       string `json:"mode,omitempty"`
	// Plan is the plan the organization is on.
	Plan string `json:"plan"`
	// SetByOperator is whether the deployment's operator set the plan
	// (ADR-022). Checkout does not change it, so a page offers no other
	// plan; the billing portal still manages a paid subscription.
	SetByOperator bool `json:"setByOperator,omitempty"`
	// Subscription is the organization's subscription, if it ever had one.
	Subscription *SubscriptionStatus `json:"subscription,omitempty"`
	// CanManage is whether the person may choose a plan and open the
	// billing portal.
	CanManage bool `json:"canManage"`
	// Pricing is the spec arranged for a page to render.
	Pricing pricingspec.PricingView `json:"pricing"`
}

// SubscriptionStatus is the stored state of an organization's subscription.
type SubscriptionStatus struct {
	Plan              string    `json:"plan"`
	Status            string    `json:"status"`
	CurrentPeriodEnd  time.Time `json:"currentPeriodEnd"`
	CancelAtPeriodEnd bool      `json:"cancelAtPeriodEnd"`
	// Paid is whether a payment provider subscription stands behind it,
	// which the billing portal manages.
	Paid bool `json:"paid"`
}

// Console serves the console's billing section.
type Console struct {
	cfg      ConsoleConfig
	checkout *Checkout
	mux      *http.ServeMux
}

type principalKey struct{}

// NewConsole checks cfg and returns the section's handler.
func NewConsole(cfg ConsoleConfig) (*Console, error) {
	if cfg.Spec == nil || cfg.DB == nil || cfg.Principal == nil || cfg.WriteAuthError == nil || cfg.Role == nil {
		return nil, errors.New("billing: the console needs a spec, a database, Principal, WriteAuthError and Role")
	}
	if len(cfg.ManageRoles) == 0 {
		cfg.ManageRoles = marketplace.DefaultPurchaseRoles
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	c := &Console{cfg: cfg, mux: http.NewServeMux()}
	if cfg.Checkout != nil {
		co := *cfg.Checkout
		co.Caller = func(ctx context.Context) (uuid.UUID, error) {
			id, ok := ctx.Value(principalKey{}).(uuid.UUID)
			if !ok {
				return uuid.Nil, marketplace.ErrNoCaller
			}
			return id, nil
		}
		co.Organization = func(r *http.Request) (uuid.UUID, error) {
			id, err := uuid.Parse(r.PathValue("org"))
			if err != nil {
				return uuid.Nil, ErrNoOrganization
			}
			return id, nil
		}
		co.Purchases = marketplace.PurchaseAuthorizerFunc(func(ctx context.Context, principal, org uuid.UUID) (bool, error) {
			role, err := cfg.Role(ctx, principal, org)
			if err != nil {
				return false, err
			}
			return c.manages(role), nil
		})
		checkout, err := NewCheckout(co)
		if err != nil {
			return nil, err
		}
		c.checkout = checkout
	}
	c.mux.Handle("GET "+ConsolePath, c.member(http.HandlerFunc(c.status)))
	c.mux.Handle("POST "+ConsolePath+"/checkout", c.member(c.pay(func(co *Checkout) http.Handler { return co.PlanHandler() })))
	c.mux.Handle("POST "+ConsolePath+"/portal", c.member(c.pay(func(co *Checkout) http.Handler { return co.PortalHandler() })))
	return c, nil
}

// ServeHTTP implements [http.Handler].
func (c *Console) ServeHTTP(w http.ResponseWriter, r *http.Request) { c.mux.ServeHTTP(w, r) }

func (c *Console) manages(role string) bool { return slices.Contains(c.cfg.ManageRoles, role) }

// member admits the organization's members, with the person in the
// request's context. Anyone else is told the organization does not exist.
func (c *Console) member(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := c.cfg.Principal(r)
		if err != nil {
			c.cfg.WriteAuthError(w, err)
			return
		}
		org, err := uuid.Parse(r.PathValue("org"))
		if err != nil {
			writeConsoleJSON(w, http.StatusNotFound, map[string]string{"error": "organization not found"})
			return
		}
		role, err := c.cfg.Role(r.Context(), principal, org)
		if err != nil {
			c.cfg.Logger.ErrorContext(r.Context(), "billing: organization role", "error", err)
			writeConsoleJSON(w, http.StatusInternalServerError, map[string]string{"error": "billing is unavailable"})
			return
		}
		if role == "" {
			writeConsoleJSON(w, http.StatusNotFound, map[string]string{"error": "organization not found"})
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, principal)
		ctx = context.WithValue(ctx, roleKey{}, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type roleKey struct{}

// pay serves a checkout endpoint, or refuses it in free mode.
func (c *Console) pay(h func(*Checkout) http.Handler) http.Handler {
	if c.checkout == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeConsoleJSON(w, http.StatusConflict, map[string]string{"error": "payments are not set up for this deployment"})
		})
	}
	return h(c.checkout)
}

func (c *Console) status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org, err := uuid.Parse(r.PathValue("org"))
	if err != nil {
		writeConsoleJSON(w, http.StatusNotFound, map[string]string{"error": "organization not found"})
		return
	}
	plan, sub, err := OrganizationPlan(ctx, c.cfg.DB, c.cfg.Spec, org, c.checkout != nil)
	if err != nil {
		c.cfg.Logger.ErrorContext(ctx, "billing: reading the organization's plan", "error", err)
		writeConsoleJSON(w, http.StatusInternalServerError, map[string]string{"error": "billing is unavailable"})
		return
	}
	role, _ := ctx.Value(roleKey{}).(string) // set by member; a missing role manages nothing
	out := Status{
		Configured: c.checkout != nil,
		Mode:       c.cfg.Mode,
		Plan:       plan.ID,
		CanManage:  c.checkout != nil && c.manages(role),
		Pricing:    c.cfg.Spec.PricingView(),
	}
	if sub != nil {
		out.SetByOperator = sub.OperatorPlan != ""
		out.Subscription = &SubscriptionStatus{
			Plan: sub.PlanTier, Status: string(sub.Status), CurrentPeriodEnd: sub.CurrentPeriodEnd,
			CancelAtPeriodEnd: sub.CancelAtPeriodEnd, Paid: sub.StripeSubscriptionID != "",
		}
	}
	writeConsoleJSON(w, http.StatusOK, out)
}

func writeConsoleJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status is sent; a failed write means the client went away.
		slog.Default().Debug("billing: writing a response", "error", err)
	}
}
