package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/payforge"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/billingcustomer"
	"github.com/plexusone/systemforge/identity/ent/billingevent"
)

// ErrCustomerConflict is returned by LinkCustomer when the provider
// customer is already linked to another organization.
var ErrCustomerConflict = errors.New("billing: customer belongs to another organization")

// Store is payforge's Store on the SystemForge Ent client. It is portable
// across the Ent dialects SystemForge supports; the guarantee that an event
// is processed once rests on the unique event_id column, so it holds
// across instances sharing a database.
type Store struct {
	db *ent.Client
}

var _ payforge.Store = (*Store)(nil)

// NewStore returns a Store. It panics on a nil client, a programming error.
func NewStore(db *ent.Client) *Store {
	if db == nil {
		panic("billing: NewStore needs an Ent client")
	}
	return &Store{db: db}
}

// Seen implements payforge.Store.
func (s *Store) Seen(ctx context.Context, eventID string) (bool, error) {
	ok, err := s.db.BillingEvent.Query().Where(billingevent.EventIDEQ(eventID)).Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("billing: check event: %w", err)
	}
	return ok, nil
}

// MarkSeen implements payforge.Store. Marking an event twice, or from two
// instances at once, is harmless: the unique constraint keeps one row.
func (s *Store) MarkSeen(ctx context.Context, eventID string) error {
	err := s.db.BillingEvent.Create().SetEventID(eventID).Exec(ctx)
	if err != nil && !ent.IsConstraintError(err) {
		return fmt.Errorf("billing: record event: %w", err)
	}
	return nil
}

// PruneEvents forgets events processed before cutoff and reports how many.
// The provider redelivers an event for a few days at most, so a cutoff of
// a month or more keeps every event that can still arrive.
func (s *Store) PruneEvents(ctx context.Context, cutoff time.Time) (int, error) {
	n, err := s.db.BillingEvent.Delete().Where(billingevent.CreatedAtLT(cutoff)).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("billing: prune events: %w", err)
	}
	return n, nil
}

// SubjectForCustomer implements payforge.Store. The subject is the
// organization ID.
func (s *Store) SubjectForCustomer(ctx context.Context, customerID string) (string, error) {
	c, err := s.db.BillingCustomer.Query().Where(billingcustomer.CustomerIDEQ(customerID)).Only(ctx)
	if ent.IsNotFound(err) {
		return "", payforge.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("billing: find customer: %w", err)
	}
	return c.OrganizationID.String(), nil
}

// CustomerForOrganization returns the provider customer an organization
// pays through, or payforge.ErrNotFound.
func (s *Store) CustomerForOrganization(ctx context.Context, orgID uuid.UUID) (string, error) {
	c, err := s.db.BillingCustomer.Query().Where(billingcustomer.OrganizationIDEQ(orgID)).Only(ctx)
	if ent.IsNotFound(err) {
		return "", payforge.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("billing: find customer: %w", err)
	}
	return c.CustomerID, nil
}

// LinkCustomer records that an organization pays through a provider
// customer. Linking the same pair again does nothing. An organization that
// had another customer is moved to this one. A customer already linked to
// another organization is refused with ErrCustomerConflict.
func (s *Store) LinkCustomer(ctx context.Context, customerID string, orgID uuid.UUID) error {
	if customerID == "" || orgID == uuid.Nil {
		return errors.New("billing: link customer: empty customer or organization")
	}
	return withTx(ctx, s.db, func(tx *ent.Tx) error { return linkCustomer(ctx, tx.Client(), customerID, orgID) })
}

// linkCustomer is LinkCustomer on a transaction's client.
func linkCustomer(ctx context.Context, c *ent.Client, customerID string, orgID uuid.UUID) error {
	existing, err := c.BillingCustomer.Query().Where(billingcustomer.CustomerIDEQ(customerID)).Only(ctx)
	switch {
	case err == nil:
		if existing.OrganizationID != orgID {
			return ErrCustomerConflict
		}
		return nil
	case !ent.IsNotFound(err):
		return fmt.Errorf("billing: find customer: %w", err)
	}
	n, err := c.BillingCustomer.Update().
		Where(billingcustomer.OrganizationIDEQ(orgID)).
		SetCustomerID(customerID).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("billing: move customer: %w", err)
	}
	if n > 0 {
		return nil
	}
	if err := c.BillingCustomer.Create().SetCustomerID(customerID).SetOrganizationID(orgID).Exec(ctx); err != nil {
		if ent.IsConstraintError(err) {
			return ErrCustomerConflict
		}
		return fmt.Errorf("billing: link customer: %w", err)
	}
	return nil
}

// withTx runs fn in a transaction, committing when fn returns nil and
// rolling back otherwise.
func withTx(ctx context.Context, db *ent.Client, fn func(tx *ent.Tx) error) error {
	tx, err := db.Tx(ctx)
	if err != nil {
		return fmt.Errorf("billing: start transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil {
			return errors.Join(err, fmt.Errorf("billing: roll back: %w", rerr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("billing: commit: %w", err)
	}
	return nil
}
