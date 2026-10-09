package marketplace

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/subscription"
)

// EntSubscriptionService is an Ent-backed implementation of SubscriptionService.
type EntSubscriptionService struct {
	client *ent.Client
}

// NewEntSubscriptionService creates a new Ent-backed subscription service.
func NewEntSubscriptionService(client *ent.Client) *EntSubscriptionService {
	return &EntSubscriptionService{
		client: client,
	}
}

// Create creates a new subscription.
func (s *EntSubscriptionService) Create(ctx context.Context, sub *Subscription) error {
	builder := s.client.Subscription.Create().
		SetID(sub.ID).
		SetOrganizationID(sub.OrganizationID).
		SetPlanTier(sub.PlanTier).
		SetStatus(subscription.Status(sub.Status)).
		SetCurrentPeriodStart(sub.CurrentPeriodStart).
		SetCurrentPeriodEnd(sub.CurrentPeriodEnd)

	if sub.ListingID != nil {
		builder.SetListingID(*sub.ListingID)
	}
	if sub.StripeSubscriptionID != "" {
		builder.SetStripeSubscriptionID(sub.StripeSubscriptionID)
	}
	if sub.StripeCustomerID != "" {
		builder.SetStripeCustomerID(sub.StripeCustomerID)
	}

	created, err := builder.Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to create subscription: %w", err)
	}

	sub.ID = created.ID
	sub.CreatedAt = created.CreatedAt
	sub.UpdatedAt = created.UpdatedAt

	return nil
}

// Get retrieves a subscription by ID.
func (s *EntSubscriptionService) Get(ctx context.Context, id uuid.UUID) (*Subscription, error) {
	entSub, err := s.client.Subscription.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrSubscriptionNotFound
		}
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}
	return entSubscriptionToSubscription(entSub), nil
}

// GetByOrg retrieves the organization-wide platform subscription of an
// organization, the one with no listing. Use ListByOrg for the
// per-listing subscriptions.
func (s *EntSubscriptionService) GetByOrg(ctx context.Context, orgID uuid.UUID) (*Subscription, error) {
	entSub, err := s.client.Subscription.Query().
		Where(subscription.OrganizationIDEQ(orgID), subscription.ListingIDIsNil()).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrSubscriptionNotFound
		}
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}
	return entSubscriptionToSubscription(entSub), nil
}

// ListByOrg lists every subscription of an organization: the platform
// subscription and those for individual listings.
func (s *EntSubscriptionService) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*Subscription, error) {
	rows, err := s.client.Subscription.Query().
		Where(subscription.OrganizationIDEQ(orgID)).
		Order(ent.Asc(subscription.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list subscriptions: %w", err)
	}
	out := make([]*Subscription, len(rows))
	for i, r := range rows {
		out[i] = entSubscriptionToSubscription(r)
	}
	return out, nil
}

// Update updates a subscription's details.
func (s *EntSubscriptionService) Update(ctx context.Context, sub *Subscription) error {
	builder := s.client.Subscription.UpdateOneID(sub.ID).
		SetPlanTier(sub.PlanTier).
		SetStatus(subscription.Status(sub.Status)).
		SetCurrentPeriodStart(sub.CurrentPeriodStart).
		SetCurrentPeriodEnd(sub.CurrentPeriodEnd).
		SetCancelAtPeriodEnd(sub.CancelAtPeriodEnd)

	if sub.StripeSubscriptionID != "" {
		builder.SetStripeSubscriptionID(sub.StripeSubscriptionID)
	}
	if sub.StripeCustomerID != "" {
		builder.SetStripeCustomerID(sub.StripeCustomerID)
	}

	_, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrSubscriptionNotFound
		}
		return fmt.Errorf("failed to update subscription: %w", err)
	}
	return nil
}

// Cancel cancels a subscription at period end.
func (s *EntSubscriptionService) Cancel(ctx context.Context, id uuid.UUID) error {
	_, err := s.client.Subscription.UpdateOneID(id).
		SetCancelAtPeriodEnd(true).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrSubscriptionNotFound
		}
		return fmt.Errorf("failed to cancel subscription: %w", err)
	}
	return nil
}

// CancelImmediately cancels a subscription immediately.
func (s *EntSubscriptionService) CancelImmediately(ctx context.Context, id uuid.UUID) error {
	_, err := s.client.Subscription.UpdateOneID(id).
		SetStatus(subscription.StatusCanceled).
		SetCurrentPeriodEnd(time.Now()).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrSubscriptionNotFound
		}
		return fmt.Errorf("failed to cancel subscription: %w", err)
	}
	return nil
}

// Reactivate reactivates a canceled subscription.
func (s *EntSubscriptionService) Reactivate(ctx context.Context, id uuid.UUID) error {
	_, err := s.client.Subscription.UpdateOneID(id).
		SetStatus(subscription.StatusActive).
		SetCancelAtPeriodEnd(false).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrSubscriptionNotFound
		}
		return fmt.Errorf("failed to reactivate subscription: %w", err)
	}
	return nil
}

// ChangePlan changes the subscription plan.
func (s *EntSubscriptionService) ChangePlan(ctx context.Context, id uuid.UUID, newPlan string) error {
	_, err := s.client.Subscription.UpdateOneID(id).
		SetPlanTier(newPlan).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrSubscriptionNotFound
		}
		return fmt.Errorf("failed to change subscription plan: %w", err)
	}
	return nil
}

// IsActive checks if an organization has an active subscription.
func (s *EntSubscriptionService) IsActive(ctx context.Context, orgID uuid.UUID) (bool, error) {
	sub, err := s.GetByOrg(ctx, orgID)
	if err != nil {
		if err == ErrSubscriptionNotFound {
			return false, nil
		}
		return false, err
	}
	return sub.IsActive(), nil
}

// GetPlanTier returns the current plan tier for an organization.
func (s *EntSubscriptionService) GetPlanTier(ctx context.Context, orgID uuid.UUID) (string, error) {
	sub, err := s.GetByOrg(ctx, orgID)
	if err != nil {
		if err == ErrSubscriptionNotFound {
			return PlanTierFree, nil
		}
		return "", err
	}
	return sub.PlanTier, nil
}

// entSubscriptionToSubscription converts an Ent Subscription to a marketplace.Subscription.
func entSubscriptionToSubscription(es *ent.Subscription) *Subscription {
	sub := &Subscription{
		ID:                 es.ID,
		OrganizationID:     es.OrganizationID,
		PlanTier:           es.PlanTier,
		Status:             SubscriptionStatus(es.Status),
		CurrentPeriodStart: es.CurrentPeriodStart,
		CurrentPeriodEnd:   es.CurrentPeriodEnd,
		CancelAtPeriodEnd:  es.CancelAtPeriodEnd,
		CreatedAt:          es.CreatedAt,
		UpdatedAt:          es.UpdatedAt,
	}

	sub.ListingID = es.ListingID
	if es.StripeSubscriptionID != nil {
		sub.StripeSubscriptionID = *es.StripeSubscriptionID
	}
	if es.StripeCustomerID != nil {
		sub.StripeCustomerID = *es.StripeCustomerID
	}

	return sub
}

// Ensure EntSubscriptionService implements SubscriptionService.
var _ SubscriptionService = (*EntSubscriptionService)(nil)
