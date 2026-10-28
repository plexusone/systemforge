package billing

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/plexusone/payforge"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/billingseller"
)

// Order is a one-time checkout for a marketplace listing, recorded when the
// checkout is created.
type Order struct {
	SessionID      string
	ListingID      uuid.UUID
	OrganizationID uuid.UUID
	PurchaserID    uuid.UUID
	AmountCents    int64
}

// RecordOrder records a checkout before the buyer is sent to it, so its
// payment and refunds are matched to the listing and organization from
// this record, never from what the provider sends back.
func (s *Store) RecordOrder(ctx context.Context, o Order) error {
	if o.SessionID == "" || o.ListingID == uuid.Nil || o.OrganizationID == uuid.Nil || o.PurchaserID == uuid.Nil {
		return errors.New("billing: record order: missing field")
	}
	err := s.db.BillingOrder.Create().
		SetSessionID(o.SessionID).
		SetListingID(o.ListingID).
		SetOrganizationID(o.OrganizationID).
		SetPurchaserID(o.PurchaserID).
		SetAmountCents(o.AmountCents).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("billing: record order: %w", err)
	}
	return nil
}

// Seller is a selling organization's connected account.
type Seller struct {
	OrganizationID   uuid.UUID
	AccountID        string
	ChargesEnabled   bool
	PayoutsEnabled   bool
	DetailsSubmitted bool
}

// SellerFor returns an organization's connected account, or
// payforge.ErrNotFound.
func (s *Store) SellerFor(ctx context.Context, orgID uuid.UUID) (Seller, error) {
	row, err := s.db.BillingSeller.Query().Where(billingseller.OrganizationIDEQ(orgID)).Only(ctx)
	if ent.IsNotFound(err) {
		return Seller{}, payforge.ErrNotFound
	}
	if err != nil {
		return Seller{}, fmt.Errorf("billing: find seller: %w", err)
	}
	return Seller{
		OrganizationID: row.OrganizationID, AccountID: row.AccountID, ChargesEnabled: row.ChargesEnabled,
		PayoutsEnabled: row.PayoutsEnabled, DetailsSubmitted: row.DetailsSubmitted,
	}, nil
}

// LinkSeller records an organization's connected account, as returned by
// payforge's Connect.CreateAccount. It cannot sell until the provider
// reports that charges are enabled. Linking the same pair again does
// nothing.
func (s *Store) LinkSeller(ctx context.Context, orgID uuid.UUID, accountID string) error {
	return withTx(ctx, s.db, func(tx *ent.Tx) error {
		_, err := upsertSeller(ctx, tx.Client(), payforge.SellerAccount{Subject: orgID.String(), AccountID: accountID}, false)
		return err
	})
}

// errSellerConflict means a connected account is recorded for another
// organization.
var errSellerConflict = errors.New("billing: the connected account belongs to another organization")

// upsertSeller records a seller's account; with state it also sets what the
// account may do. It returns the organization.
func upsertSeller(ctx context.Context, c *ent.Client, a payforge.SellerAccount, state bool) (uuid.UUID, error) {
	org, err := uuid.Parse(a.Subject)
	if err != nil || a.AccountID == "" {
		return uuid.Nil, errors.New("billing: seller: invalid organization or account")
	}
	row, err := c.BillingSeller.Query().Where(billingseller.AccountIDEQ(a.AccountID)).Only(ctx)
	switch {
	case err == nil:
		if row.OrganizationID != org {
			return uuid.Nil, errSellerConflict
		}
		if !state {
			return org, nil
		}
		err = row.Update().SetChargesEnabled(a.ChargesEnabled).SetPayoutsEnabled(a.PayoutsEnabled).
			SetDetailsSubmitted(a.DetailsSubmitted).Exec(ctx)
		if err != nil {
			return uuid.Nil, fmt.Errorf("billing: update seller: %w", err)
		}
		return org, nil
	case !ent.IsNotFound(err):
		return uuid.Nil, fmt.Errorf("billing: find seller: %w", err)
	}
	// A new account for the organization replaces the one it had.
	if _, err := c.BillingSeller.Delete().Where(billingseller.OrganizationIDEQ(org)).Exec(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("billing: replace seller: %w", err)
	}
	err = c.BillingSeller.Create().SetOrganizationID(org).SetAccountID(a.AccountID).
		SetChargesEnabled(state && a.ChargesEnabled).SetPayoutsEnabled(state && a.PayoutsEnabled).
		SetDetailsSubmitted(state && a.DetailsSubmitted).Exec(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("billing: record seller: %w", err)
	}
	return org, nil
}

// SellerGate is a marketplace.PublishGate: an organization may publish a
// paid listing while its connected account can take charges.
type SellerGate struct {
	store *Store
}

// NewSellerGate returns a SellerGate over store.
func NewSellerGate(store *Store) *SellerGate { return &SellerGate{store: store} }

// CanPublish implements marketplace.PublishGate.
func (g *SellerGate) CanPublish(ctx context.Context, creatorOrgID uuid.UUID) (bool, error) {
	s, err := g.store.SellerFor(ctx, creatorOrgID)
	if errors.Is(err, payforge.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return s.ChargesEnabled, nil
}
