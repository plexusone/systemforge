package marketplace

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/organization"
)

// EntitlementOption configures EntitlementSource.
type EntitlementOption func(*entitlementConfig)

type entitlementConfig struct {
	defaults []string
}

// WithDefaultEntitlements declares applications every organization is
// entitled to, with unlimited seats: applications that are free for
// everyone, or a deployment that does not sell access through the
// marketplace. It is the deployment's marketplace.default_entitlements.
func WithDefaultEntitlements(applications ...string) EntitlementOption {
	return func(c *entitlementConfig) { c.defaults = append(c.defaults, applications...) }
}

// EntitlementSource returns an organization.EntitlementSource that
// derives an organization's entitlements from its subscriptions, its
// valid licenses and the deployment's default entitlements.
//
// A subscription or license grants an application when its listing names
// one (Listing.Application). The organization-wide platform subscription
// has no listing and grants none; it is reported for its tier. A
// seat-based license carries its seat count. Any of subs, licenses and
// listings may be nil to leave that source out; without listings no
// subscription or license grants an application. subs that also
// implements SubscriptionLister contributes every subscription of the
// organization, otherwise only its platform subscription.
func EntitlementSource(subs SubscriptionService, licenses LicenseService, listings ListingService, opts ...EntitlementOption) organization.EntitlementSource {
	var cfg entitlementConfig
	for _, o := range opts {
		o(&cfg)
	}
	e := &entitler{subs: subs, licenses: licenses, listings: listings, defaults: cfg.defaults}
	return e.entitlements
}

type entitler struct {
	subs     SubscriptionService
	licenses LicenseService
	listings ListingService
	defaults []string
}

func (e *entitler) application(ctx context.Context, listingID uuid.UUID, cache map[uuid.UUID]string) (string, error) {
	if e.listings == nil {
		return "", nil
	}
	if app, ok := cache[listingID]; ok {
		return app, nil
	}
	l, err := e.listings.Get(ctx, listingID)
	if errors.Is(err, ErrListingNotFound) {
		cache[listingID] = ""
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("entitlements: listing: %w", err)
	}
	cache[listingID] = l.Application
	return l.Application, nil
}

func (e *entitler) subscriptions(ctx context.Context, orgID uuid.UUID) ([]*Subscription, error) {
	if lister, ok := e.subs.(SubscriptionLister); ok {
		list, err := lister.ListByOrg(ctx, orgID)
		if err != nil {
			return nil, fmt.Errorf("entitlements: subscriptions: %w", err)
		}
		return list, nil
	}
	sub, err := e.subs.GetByOrg(ctx, orgID)
	switch {
	case errors.Is(err, ErrSubscriptionNotFound):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("entitlements: subscription: %w", err)
	}
	return []*Subscription{sub}, nil
}

func (e *entitler) entitlements(ctx context.Context, orgID uuid.UUID) ([]organization.Entitlement, error) {
	out := []organization.Entitlement{}
	apps := map[uuid.UUID]string{}
	if e.subs != nil {
		list, err := e.subscriptions(ctx, orgID)
		if err != nil {
			return nil, err
		}
		for _, sub := range list {
			if !sub.IsActive() {
				continue
			}
			ent := organization.Entitlement{
				Source: organization.EntitlementSourceSubscription,
				Tier:   sub.PlanTier,
			}
			if sub.ListingID != nil {
				ent.ListingID = sub.ListingID.String()
				if ent.Application, err = e.application(ctx, *sub.ListingID, apps); err != nil {
					return nil, err
				}
			}
			if !sub.CurrentPeriodEnd.IsZero() {
				end := sub.CurrentPeriodEnd
				ent.ValidUntil = &end
			}
			out = append(out, ent)
		}
	}
	if e.licenses != nil {
		list, err := e.licenses.List(ctx, orgID)
		if err != nil {
			return nil, fmt.Errorf("entitlements: licenses: %w", err)
		}
		for _, l := range list {
			if !l.IsValid() {
				continue
			}
			ent := organization.Entitlement{
				Source:     organization.EntitlementSourceLicense,
				ListingID:  l.ListingID.String(),
				Tier:       string(l.LicenseType),
				ValidUntil: l.ValidUntil,
			}
			if ent.Application, err = e.application(ctx, l.ListingID, apps); err != nil {
				return nil, err
			}
			if l.LicenseType == LicenseSeatBased && l.Seats != nil {
				seats := *l.Seats
				ent.Seats = &seats
			}
			out = append(out, ent)
		}
	}
	for _, app := range e.defaults {
		out = append(out, organization.Entitlement{
			Source:      organization.EntitlementSourceDefault,
			Application: app,
		})
	}
	return out, nil
}

// ApproleOptions returns the approle.Service options that make src the
// source of which applications an organization may assign roles in, and
// how many seats each has. An application is entitled when any
// entitlement names it. Its seat limit is the sum of the seats of its
// seat-based licenses, and none when any entitlement for it is not
// seat-limited (a subscription, an unlimited license, a default).
func ApproleOptions(src organization.EntitlementSource) []approle.Option {
	return []approle.Option{approle.WithEntitlementGrants(func(ctx context.Context, orgID uuid.UUID) (map[string]approle.Grant, error) {
		list, err := src(ctx, orgID)
		if err != nil {
			return nil, err
		}
		return grantsFrom(list), nil
	})}
}

func grantsFrom(list []organization.Entitlement) map[string]approle.Grant {
	type tally struct {
		seats     int
		unlimited bool
	}
	by := map[string]*tally{}
	for _, e := range list {
		if e.Application == "" {
			continue
		}
		t := by[e.Application]
		if t == nil {
			t = &tally{}
			by[e.Application] = t
		}
		if e.Seats == nil {
			t.unlimited = true
		} else {
			t.seats += *e.Seats
		}
	}
	out := make(map[string]approle.Grant, len(by))
	for app, t := range by {
		g := approle.Grant{}
		if !t.unlimited {
			seats := t.seats
			g.SeatLimit = &seats
		}
		out[app] = g
	}
	return out
}

// WarnIfNoEntitlements logs a warning when the deployment registers
// applications but nothing can entitle an organization to them: no
// default entitlement and no listing that names an application. Every
// organization is then refused every application role (ADR-007). Call it
// at startup with the registered application identifiers; it reports
// whether it warned.
func WarnIfNoEntitlements(ctx context.Context, logger *slog.Logger, listings ListingService, registered []string, opts ...EntitlementOption) (bool, error) {
	if len(registered) == 0 {
		return false, nil
	}
	var cfg entitlementConfig
	for _, o := range opts {
		o(&cfg)
	}
	if len(cfg.defaults) > 0 {
		return false, nil
	}
	if listings != nil {
		all, err := listings.List(ctx, ListListingsOptions{})
		if err != nil {
			return false, fmt.Errorf("entitlements: listing listings: %w", err)
		}
		for _, l := range all {
			if l.Application != "" {
				return false, nil
			}
		}
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger.WarnContext(ctx, "no organization can be entitled to any registered application: configure default entitlements or set an application on a marketplace listing",
		"registered_applications", registered)
	return true, nil
}
