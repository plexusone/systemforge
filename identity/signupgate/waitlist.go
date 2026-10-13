package signupgate

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/signupwaitlistentry"
	"github.com/plexusone/systemforge/identity/systemauth"
)

// WaitlistEntry is an address waiting to be told that sign-up is open.
type WaitlistEntry struct {
	Email          string
	ConsentVersion string
	ConsentText    string
	// CreatedAt is when the address first joined; UpdatedAt when it was
	// last submitted.
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Waitlist stores the addresses that asked to be notified while a
// deployment is invite-only. It sends nothing itself: operators export it.
type Waitlist struct {
	client *ent.Client
}

var _ systemauth.SignupWaitlist = (*Waitlist)(nil)

// NewWaitlist returns a Waitlist over client.
func NewWaitlist(client *ent.Client) *Waitlist {
	return &Waitlist{client: client}
}

// Join adds an address, or refreshes the consent recorded for one already
// listed. Either way the caller learns nothing about whether it was listed
// before, so a public form built on it cannot be used to probe addresses.
func (w *Waitlist) Join(ctx context.Context, email, consentVersion, consentText string) error {
	email, err := NormalizeEmail(email)
	if err != nil {
		return err
	}
	err = w.client.SignupWaitlistEntry.Create().
		SetEmail(email).
		SetConsentVersion(consentVersion).
		SetConsentText(consentText).
		OnConflictColumns(signupwaitlistentry.FieldEmail).
		Update(func(u *ent.SignupWaitlistEntryUpsert) {
			u.UpdateConsentVersion().UpdateConsentText().UpdateUpdatedAt()
		}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("signupgate: joining the waitlist: %w", err)
	}
	return nil
}

// List returns every entry, oldest first.
func (w *Waitlist) List(ctx context.Context) ([]WaitlistEntry, error) {
	rows, err := w.client.SignupWaitlistEntry.Query().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("signupgate: listing the waitlist: %w", err)
	}
	out := make([]WaitlistEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, WaitlistEntry{
			Email: r.Email, ConsentVersion: r.ConsentVersion, ConsentText: r.ConsentText,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].Email < out[j].Email
	})
	return out, nil
}

// Remove deletes an address, for example on request. It returns
// ErrNotFound when the address is not listed.
func (w *Waitlist) Remove(ctx context.Context, email string) error {
	email, err := NormalizeEmail(email)
	if err != nil {
		return err
	}
	n, err := w.client.SignupWaitlistEntry.Delete().Where(signupwaitlistentry.EmailEQ(email)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("signupgate: removing from the waitlist: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, email)
	}
	return nil
}

// WriteWaitlistCSV writes entries as CSV with a header row: email, joined
// and last submitted times (RFC 3339, UTC) and the consent version.
func WriteWaitlistCSV(out io.Writer, entries []WaitlistEntry) error {
	cw := csv.NewWriter(out)
	if err := cw.Write([]string{"email", "joined_at", "last_submitted_at", "consent_version"}); err != nil {
		return err
	}
	for _, e := range entries {
		if err := cw.Write([]string{
			e.Email, e.CreatedAt.UTC().Format(time.RFC3339), e.UpdatedAt.UTC().Format(time.RFC3339), e.ConsentVersion,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
