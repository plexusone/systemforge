package billing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/plexusone/systemspec-pricingpackaging/pricingspec"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/subscription"
)

// Errors of the operator's plans.
var (
	// ErrUnknownPlan means the plan is not in the pricing spec.
	ErrUnknownPlan = errors.New("billing: the plan is not in the pricing spec")
	// ErrUnknownOrganization means there is no such organization.
	ErrUnknownOrganization = errors.New("billing: no such organization")
	// ErrInvalidNote means the note is too long or not one line.
	ErrInvalidNote = errors.New("billing: the note must be one line of at most 200 characters")
)

// MaxOperatorNote is the longest note on an operator's plan, in characters.
const MaxOperatorNote = 200

// OperatorPlan is a plan the deployment's operator set for an organization
// (ADR-022).
type OperatorPlan struct {
	OrganizationID uuid.UUID
	Plan           string
	Note           string
	SetAt          time.Time
}

// SetOperatorPlan puts an organization on a plan of the spec by hand, for an
// organization that runs or tests the service, or one given a plan without
// paying. The plan may be any plan of the spec, internal plans included,
// and stays until ClearOperatorPlan: billing events change the platform
// subscription's own plan and status but never the operator's plan, and
// checkout refuses to sell the organization a plan while it is set. The
// organization keeps any paid subscription, which it manages in the
// billing portal.
func SetOperatorPlan(ctx context.Context, db *ent.Client, spec *pricingspec.Spec, org uuid.UUID, plan, note string) error {
	if _, ok := spec.Plan(plan); !ok {
		return fmt.Errorf("%w: %q", ErrUnknownPlan, plan)
	}
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(note) > MaxOperatorNote || strings.ContainsFunc(note, unicode.IsControl) {
		return ErrInvalidNote
	}
	return withTx(ctx, db, func(tx *ent.Tx) error {
		c := tx.Client()
		ok, err := c.Organization.Query().Where(organization.IDEQ(org)).Exist(ctx)
		if err != nil {
			return fmt.Errorf("billing: find organization: %w", err)
		}
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownOrganization, org)
		}
		now := time.Now()
		row, err := platformSubscription(ctx, c, org)
		if err != nil {
			return err
		}
		if row != nil {
			err = row.Update().SetOperatorPlan(plan).SetOperatorNote(note).SetOperatorSetAt(now).Exec(ctx)
		} else {
			// The organization never had a subscription: it is on the
			// default plan, as the sink records one.
			err = c.Subscription.Create().SetOrganizationID(org).
				SetPlanTier(spec.PlanOrDefault("").ID).SetStatus(subscription.StatusActive).SetCurrentPeriodEnd(now).
				SetOperatorPlan(plan).SetOperatorNote(note).SetOperatorSetAt(now).Exec(ctx)
		}
		if err != nil {
			return fmt.Errorf("billing: set the operator's plan: %w", err)
		}
		return nil
	})
}

// ClearOperatorPlan removes the plan the operator set, so the organization
// is on its subscription's plan again, or the default plan. It reports
// whether there was one.
func ClearOperatorPlan(ctx context.Context, db *ent.Client, org uuid.UUID) (bool, error) {
	n, err := db.Subscription.Update().
		Where(subscription.OrganizationIDEQ(org), subscription.ListingIDIsNil(), subscription.OperatorPlanNotNil()).
		ClearOperatorPlan().SetOperatorNote("").ClearOperatorSetAt().Save(ctx)
	if err != nil {
		return false, fmt.Errorf("billing: clear the operator's plan: %w", err)
	}
	return n > 0, nil
}

// OperatorPlanOf returns the plan the operator set for an organization, if
// there is one.
func OperatorPlanOf(ctx context.Context, db *ent.Client, org uuid.UUID) (OperatorPlan, bool, error) {
	row, err := platformSubscription(ctx, db, org)
	if err != nil || row == nil || row.OperatorPlan == nil {
		return OperatorPlan{}, false, err
	}
	return operatorPlan(row), true, nil
}

// OperatorPlans lists every plan an operator set, by organization.
func OperatorPlans(ctx context.Context, db *ent.Client) ([]OperatorPlan, error) {
	rows, err := db.Subscription.Query().
		Where(subscription.ListingIDIsNil(), subscription.OperatorPlanNotNil()).
		Order(ent.Asc(subscription.FieldOperatorSetAt)).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("billing: list the operator's plans: %w", err)
	}
	out := make([]OperatorPlan, 0, len(rows))
	for _, r := range rows {
		out = append(out, operatorPlan(r))
	}
	return out, nil
}

func platformSubscription(ctx context.Context, c *ent.Client, org uuid.UUID) (*ent.Subscription, error) {
	row, err := c.Subscription.Query().
		Where(subscription.OrganizationIDEQ(org), subscription.ListingIDIsNil()).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("billing: find platform subscription: %w", err)
	}
	return row, nil
}

func operatorPlan(r *ent.Subscription) OperatorPlan {
	p := OperatorPlan{OrganizationID: r.OrganizationID, Plan: *r.OperatorPlan, Note: r.OperatorNote}
	if r.OperatorSetAt != nil {
		p.SetAt = *r.OperatorSetAt
	}
	return p
}
