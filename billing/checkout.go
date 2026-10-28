package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/plexusone/payforge"
	"github.com/plexusone/systemspec-pricingpackaging/pricingspec"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/marketplace"
)

// OrganizationResolver returns the organization a request acts for. It
// returns ErrNoOrganization when the request names none.
type OrganizationResolver func(r *http.Request) (uuid.UUID, error)

// ErrNoOrganization is returned by an OrganizationResolver for a request
// that acts for no organization.
var ErrNoOrganization = errors.New("billing: the request acts for no organization")

// CredentialOrganization resolves the organization from the caller's
// credential: the organization its session or token is scoped to
// (requestprincipal.RequestPrincipal.Organization). It is the default.
func CredentialOrganization(r *http.Request) (uuid.UUID, error) {
	p, ok := requestprincipal.FromContext(r.Context())
	if !ok || p.Organization == "" {
		return uuid.Nil, ErrNoOrganization
	}
	id, err := uuid.Parse(p.Organization)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %q is not an organization ID", ErrNoOrganization, p.Organization)
	}
	return id, nil
}

// RedirectURLs are where the provider sends the buyer back to. They are
// configured on the server and never taken from a request. The checkout
// session ID is appended to a success URL.
type RedirectURLs struct {
	PlanSuccess    string
	PlanCancel     string
	ListingSuccess string
	ListingCancel  string
	PortalReturn   string
}

// CheckoutConfig configures Checkout. Billing, Spec, Store, DB, Purchases
// and Locker are required, and AllowedURLHosts must name the host of every
// URL in URLs.
type CheckoutConfig struct {
	// Billing is the payment provider, usually a payforge/stripe client.
	Billing payforge.Billing
	// Connect sells listings for their creator organizations when the spec
	// has a marketplace. Without a marketplace a listing is sold as the
	// platform's own product.
	Connect payforge.Connect
	Spec    *pricingspec.Spec
	Store   *Store
	DB      *ent.Client
	// Listings, when set, enables listing checkout.
	Listings marketplace.ListingService
	// ListingProduct is the spec's seller-set product that a listing is sold
	// as, at the listing's price. Required with Listings.
	ListingProduct string
	// Purchases decides who may buy, and open the billing portal, for an
	// organization, for example marketplace.OrgRolePurchaseAuthorizer. It is
	// required: without it nobody could be allowed, so NewCheckout refuses.
	Purchases marketplace.PurchaseAuthorizer
	// Purchasers, when set, refuses managed principals.
	Purchasers marketplace.PurchaserChecker
	// Locker is held per organization around a listing checkout. Use the
	// lifecycle's Locker. A plan checkout is serialized by the payforge
	// Stripe client's own Config.Locker, which must be the same Locker.
	Locker payforge.Locker
	// Caller identifies the purchaser. It defaults to
	// marketplace.RequestPrincipalCaller.
	Caller marketplace.CallerResolver
	// Organization finds the organization the caller acts for. It defaults
	// to CredentialOrganization.
	Organization OrganizationResolver
	URLs         RedirectURLs
	// AllowedURLHosts are the hosts redirect URLs may name. Give the
	// payforge Stripe client the same list (stripe.Config.AllowedURLHosts),
	// which refuses any other host.
	AllowedURLHosts []string
	// Logger receives the causes of failures. It defaults to slog.Default().
	Logger *slog.Logger
}

// Checkout serves checkout and the customer portal for the caller's
// organization. The organization comes from the caller's credential, the
// caller must pass Purchases for it, the provider customer is found from
// the organization on the server, and every redirect URL is configured.
// Responses are JSON: {"url": "..."} to send the browser to, or
// {"error": "..."} with a fixed message.
type Checkout struct {
	cfg CheckoutConfig
}

// NewCheckout checks cfg and returns a Checkout.
func NewCheckout(cfg CheckoutConfig) (*Checkout, error) {
	switch {
	case cfg.Billing == nil || cfg.Spec == nil || cfg.Store == nil || cfg.DB == nil:
		return nil, errors.New("billing: checkout needs billing, a spec, a store and a database")
	case cfg.Purchases == nil:
		return nil, errors.New("billing: checkout needs a purchase authorizer")
	case cfg.Locker == nil:
		return nil, errors.New("billing: checkout needs a locker")
	case cfg.Listings != nil && cfg.ListingProduct == "":
		return nil, errors.New("billing: listing checkout needs the spec product listings are sold as")
	case cfg.Listings != nil && cfg.Spec.Marketplace != nil && cfg.Connect == nil:
		return nil, errors.New("billing: the spec has a marketplace, so listing checkout needs Connect")
	}
	hosts := map[string]bool{}
	for _, h := range cfg.AllowedURLHosts {
		hosts[strings.ToLower(h)] = true
	}
	urls := map[string]string{
		"PlanSuccess": cfg.URLs.PlanSuccess, "PlanCancel": cfg.URLs.PlanCancel, "PortalReturn": cfg.URLs.PortalReturn,
	}
	if cfg.Listings != nil {
		urls["ListingSuccess"], urls["ListingCancel"] = cfg.URLs.ListingSuccess, cfg.URLs.ListingCancel
	}
	for name, raw := range urls {
		if err := checkRedirect(raw, hosts); err != nil {
			return nil, fmt.Errorf("billing: URLs.%s: %w", name, err)
		}
	}
	if cfg.Caller == nil {
		cfg.Caller = marketplace.RequestPrincipalCaller
	}
	if cfg.Organization == nil {
		cfg.Organization = CredentialOrganization
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Checkout{cfg: cfg}, nil
}

// checkRedirect requires an absolute https URL, or http on localhost, with
// no user information, on an allowed host.
func checkRedirect(raw string, hosts map[string]bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("must be an absolute URL without user information")
	}
	host := strings.ToLower(u.Hostname())
	local := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && (u.Scheme != "http" || !local) {
		return errors.New("must be https, or http on localhost")
	}
	if !local && !hosts[host] {
		return fmt.Errorf("host %q is not in AllowedURLHosts", host)
	}
	return nil
}

// Register mounts the endpoints on mux under prefix:
//
//	POST {prefix}/checkout/plan     {"plan": "pro", "interval": "month"}
//	POST {prefix}/checkout/listing  {"listing_id": "..."}
//	POST {prefix}/portal
func (c *Checkout) Register(mux *http.ServeMux, prefix string) {
	prefix = strings.TrimRight(prefix, "/")
	mux.Handle("POST "+prefix+"/checkout/plan", c.PlanHandler())
	mux.Handle("POST "+prefix+"/checkout/listing", c.ListingHandler())
	mux.Handle("POST "+prefix+"/portal", c.PortalHandler())
}

// apiError is a response with a fixed message; cause, when set, is logged
// and never sent.
type apiError struct {
	status int
	msg    string
	cause  error
}

func (e *apiError) Error() string { return e.msg }

func fail(status int, msg string, cause error) error {
	return &apiError{status: status, msg: msg, cause: cause}
}

// serve runs fn for an authorized request and writes its URL or error.
func (c *Checkout) serve(fn func(ctx context.Context, r *http.Request, caller, org uuid.UUID) (string, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			c.writeJSON(ctx, w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		caller, org, err := c.authorize(ctx, r)
		var target string
		if err == nil {
			target, err = fn(ctx, r, caller, org)
		}
		if err != nil {
			var ae *apiError
			if !errors.As(err, &ae) {
				ae = &apiError{status: http.StatusInternalServerError, msg: "billing is unavailable", cause: err}
			}
			if ae.cause != nil {
				c.cfg.Logger.ErrorContext(ctx, "billing: request failed", "path", r.URL.Path, "status", ae.status, "error", ae.cause)
			}
			c.writeJSON(ctx, w, ae.status, map[string]string{"error": ae.msg})
			return
		}
		c.writeJSON(ctx, w, http.StatusOK, map[string]string{"url": target})
	})
}

// authorize finds the caller and the organization, and checks that the
// caller may buy for it.
func (c *Checkout) authorize(ctx context.Context, r *http.Request) (caller, org uuid.UUID, err error) {
	caller, err = c.cfg.Caller(ctx)
	if errors.Is(err, marketplace.ErrNoCaller) {
		return uuid.Nil, uuid.Nil, fail(http.StatusUnauthorized, "authentication required", nil)
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, fail(http.StatusInternalServerError, "identifying caller", err)
	}
	org, err = c.cfg.Organization(r)
	if errors.Is(err, ErrNoOrganization) {
		return uuid.Nil, uuid.Nil, fail(http.StatusBadRequest, "no organization", nil)
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, fail(http.StatusInternalServerError, "identifying organization", err)
	}
	ok, err := c.cfg.Purchases.CanPurchase(ctx, caller, org)
	if err != nil {
		return uuid.Nil, uuid.Nil, fail(http.StatusInternalServerError, "checking authorization", err)
	}
	if !ok {
		return uuid.Nil, uuid.Nil, fail(http.StatusForbidden, "not allowed to manage billing for this organization", nil)
	}
	if c.cfg.Purchasers != nil {
		managed, err := c.cfg.Purchasers.IsManaged(ctx, caller)
		if err != nil {
			return uuid.Nil, uuid.Nil, fail(http.StatusInternalServerError, "checking authorization", err)
		}
		if managed {
			return uuid.Nil, uuid.Nil, fail(http.StatusForbidden, "managed accounts cannot buy", nil)
		}
	}
	return caller, org, nil
}

// PlanHandler starts a subscription checkout for one of the spec's
// self-serve plans.
func (c *Checkout) PlanHandler() http.Handler {
	return c.serve(func(ctx context.Context, r *http.Request, _, org uuid.UUID) (string, error) {
		var body struct {
			Plan     string `json:"plan"`
			Interval string `json:"interval"`
		}
		if err := decode(r, &body); err != nil {
			return "", err
		}
		subject, err := c.subject(ctx, org)
		if err != nil {
			return "", err
		}
		if err := c.ensureCustomer(ctx, subject, org); err != nil {
			return "", err
		}
		sess, err := c.cfg.Billing.CheckoutPlan(ctx, payforge.PlanCheckout{
			Subject: subject, Plan: body.Plan, Interval: pricingspec.Interval(body.Interval),
			SuccessURL: c.cfg.URLs.PlanSuccess, CancelURL: c.cfg.URLs.PlanCancel,
		})
		if err != nil {
			return "", providerError(err)
		}
		return sess.URL, nil
	})
}

// ListingHandler starts a one-time checkout for a published marketplace
// listing, at the listing's price.
func (c *Checkout) ListingHandler() http.Handler {
	return c.serve(func(ctx context.Context, r *http.Request, caller, org uuid.UUID) (string, error) {
		if c.cfg.Listings == nil {
			return "", fail(http.StatusNotImplemented, "listing checkout is not enabled", nil)
		}
		var body struct {
			ListingID string `json:"listing_id"`
		}
		if err := decode(r, &body); err != nil {
			return "", err
		}
		id, err := uuid.Parse(body.ListingID)
		if err != nil {
			return "", fail(http.StatusBadRequest, "invalid listing_id", nil)
		}
		listing, err := c.cfg.Listings.Get(ctx, id)
		if errors.Is(err, marketplace.ErrListingNotFound) {
			return "", fail(http.StatusNotFound, "listing not found", nil)
		}
		if err != nil {
			return "", fail(http.StatusInternalServerError, "billing is unavailable", err)
		}
		switch {
		case !listing.IsPublished():
			return "", fail(http.StatusNotFound, "listing not found", nil)
		case listing.CreatorOrgID == org:
			return "", fail(http.StatusBadRequest, "cannot buy your own listing", nil)
		case listing.IsFree():
			return "", fail(http.StatusBadRequest, "the listing is free", nil)
		case listing.PricingModel != marketplace.PricingOneTime:
			return "", fail(http.StatusBadRequest, "the listing cannot be bought through checkout", nil)
		case !strings.EqualFold(listing.Currency, c.cfg.Spec.Currency):
			return "", fail(http.StatusBadRequest, "the listing's currency is not supported", nil)
		}
		subject, err := c.subject(ctx, org)
		if err != nil {
			return "", err
		}

		unlock, err := c.cfg.Locker.Lock(ctx, payforge.LockKey(c.cfg.Spec.App, org.String()))
		if err != nil {
			return "", fail(http.StatusServiceUnavailable, "billing is busy; try again", err)
		}
		defer unlock()

		held, err := marketplace.NewEntLicenseService(c.cfg.DB, nil).Check(ctx, listing.ID, org)
		if err != nil {
			return "", fail(http.StatusInternalServerError, "billing is unavailable", err)
		}
		if held {
			return "", fail(http.StatusConflict, "the organization already holds this listing", nil)
		}
		if err := c.ensureCustomer(ctx, subject, org); err != nil {
			return "", err
		}
		sess, err := c.startListingCheckout(ctx, subject, listing)
		if err != nil {
			return "", err
		}
		// Recorded before the buyer sees the checkout, so its payment can
		// only arrive for a known order.
		err = c.cfg.Store.RecordOrder(ctx, Order{
			SessionID: sess.ID, ListingID: listing.ID, OrganizationID: org, PurchaserID: caller, AmountCents: listing.PriceCents,
		})
		if err != nil {
			return "", fail(http.StatusInternalServerError, "billing is unavailable", err)
		}
		return sess.URL, nil
	})
}

func (c *Checkout) startListingCheckout(ctx context.Context, subject payforge.Subject, listing *marketplace.Listing) (payforge.Session, error) {
	if c.cfg.Spec.Marketplace == nil {
		sess, err := c.cfg.Billing.CheckoutProduct(ctx, payforge.ProductCheckout{
			Subject: subject, Product: c.cfg.ListingProduct, AmountCents: listing.PriceCents,
			SuccessURL: c.cfg.URLs.ListingSuccess, CancelURL: c.cfg.URLs.ListingCancel,
		})
		if err != nil {
			return payforge.Session{}, providerError(err)
		}
		return sess, nil
	}
	seller, err := c.cfg.Store.SellerFor(ctx, listing.CreatorOrgID)
	if errors.Is(err, payforge.ErrNotFound) {
		return payforge.Session{}, fail(http.StatusConflict, "the seller cannot take payments yet", nil)
	}
	if err != nil {
		return payforge.Session{}, fail(http.StatusInternalServerError, "billing is unavailable", err)
	}
	// The seller's plan sets the platform fee; it is read from the record,
	// never from the request.
	plan, err := marketplace.NewEntSubscriptionService(c.cfg.DB).GetPlanTier(ctx, listing.CreatorOrgID)
	if err != nil {
		return payforge.Session{}, fail(http.StatusInternalServerError, "billing is unavailable", err)
	}
	sess, err := c.cfg.Connect.CheckoutSale(ctx, payforge.Sale{
		Buyer: subject, SellerAccount: seller.AccountID, SellerPlan: plan, Product: c.cfg.ListingProduct,
		AmountCents: listing.PriceCents, SuccessURL: c.cfg.URLs.ListingSuccess, CancelURL: c.cfg.URLs.ListingCancel,
	})
	if err != nil {
		return payforge.Session{}, providerError(err)
	}
	return sess, nil
}

// PortalHandler opens the provider's customer portal for the
// organization's customer.
func (c *Checkout) PortalHandler() http.Handler {
	return c.serve(func(ctx context.Context, _ *http.Request, _, org uuid.UUID) (string, error) {
		customer, err := c.cfg.Store.CustomerForOrganization(ctx, org)
		if errors.Is(err, payforge.ErrNotFound) {
			return "", fail(http.StatusNotFound, "the organization has no billing account", nil)
		}
		if err != nil {
			return "", fail(http.StatusInternalServerError, "billing is unavailable", err)
		}
		u, err := c.cfg.Billing.Portal(ctx, customer, c.cfg.URLs.PortalReturn)
		if err != nil {
			return "", providerError(err)
		}
		return u, nil
	})
}

// subject is the organization as payforge bills it.
func (c *Checkout) subject(ctx context.Context, org uuid.UUID) (payforge.Subject, error) {
	o, err := c.cfg.DB.Organization.Get(ctx, org)
	if ent.IsNotFound(err) {
		return payforge.Subject{}, fail(http.StatusNotFound, "organization not found", nil)
	}
	if err != nil {
		return payforge.Subject{}, fail(http.StatusInternalServerError, "billing is unavailable", err)
	}
	return payforge.Subject{ID: org.String(), Name: o.Name}, nil
}

// ensureCustomer finds the organization's provider customer, creating and
// linking it the first time.
func (c *Checkout) ensureCustomer(ctx context.Context, subject payforge.Subject, org uuid.UUID) error {
	_, err := c.cfg.Store.CustomerForOrganization(ctx, org)
	if err == nil {
		return nil
	}
	if !errors.Is(err, payforge.ErrNotFound) {
		return fail(http.StatusInternalServerError, "billing is unavailable", err)
	}
	customer, err := c.cfg.Billing.EnsureCustomer(ctx, subject)
	if err != nil {
		return providerError(err)
	}
	if err := c.cfg.Store.LinkCustomer(ctx, customer, org); err != nil {
		return fail(http.StatusInternalServerError, "billing is unavailable", err)
	}
	return nil
}

// providerError maps payforge's errors to fixed messages.
func providerError(err error) error {
	switch {
	case errors.Is(err, payforge.ErrUnknownPlan), errors.Is(err, payforge.ErrNotSelfServe), errors.Is(err, payforge.ErrNoPrice):
		return fail(http.StatusBadRequest, "the plan is not available", nil)
	case errors.Is(err, payforge.ErrAlreadySubscribed):
		return fail(http.StatusConflict, "the organization already has a subscription; change it in the billing portal", nil)
	case errors.Is(err, payforge.ErrSellerNotReady), errors.Is(err, payforge.ErrForeignAccount):
		return fail(http.StatusConflict, "the seller cannot take payments yet", err)
	case errors.Is(err, payforge.ErrBelowMinimum), errors.Is(err, payforge.ErrUnknownProduct), errors.Is(err, payforge.ErrAmountNotAllowed):
		return fail(http.StatusBadRequest, "the listing cannot be bought through checkout", err)
	case errors.Is(err, payforge.ErrNotConfigured):
		return fail(http.StatusNotImplemented, "billing is not configured", nil)
	default:
		// Includes ErrInvalidURL and ErrNotSynced: configuration to fix.
		return fail(http.StatusBadGateway, "the payment provider is unavailable", err)
	}
}

// decode reads a small JSON body.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fail(http.StatusBadRequest, "invalid request body", nil)
	}
	return nil
}

func (c *Checkout) writeJSON(ctx context.Context, w http.ResponseWriter, status int, v map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		c.cfg.Logger.DebugContext(ctx, "billing: writing response", "error", err)
	}
}
