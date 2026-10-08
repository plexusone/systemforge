// Package clientassertion records the JWT IDs of used client assertions so
// that a signed assertion cannot be replayed before it expires. It provides
// the JTI half of Fosite's ClientManager for Ent-backed storage.
package clientassertion

import (
	"context"
	"time"

	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/clientassertionjti"
)

// JTIStore tracks used client-assertion JWT IDs in the database.
type JTIStore struct {
	db  *ent.Client
	now func() time.Time
}

// NewJTIStore returns a JTIStore backed by db.
func NewJTIStore(db *ent.Client) *JTIStore {
	return &JTIStore{db: db, now: time.Now}
}

// Valid returns fosite.ErrJTIKnown when jti has been used and has not yet
// expired, and nil otherwise. It implements
// fosite.ClientManager.ClientAssertionJWTValid.
func (s *JTIStore) Valid(ctx context.Context, jti string) error {
	known, err := s.db.ClientAssertionJTI.Query().
		Where(
			clientassertionjti.JtiEQ(jti),
			clientassertionjti.ExpiresAtGT(s.now()),
		).
		Exist(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	if known {
		return fosite.ErrJTIKnown
	}
	return nil
}

// Mark records jti as used until exp, first forgetting JTIs that have
// expired. Marking a JTI that is still live returns fosite.ErrJTIKnown. It
// implements fosite.ClientManager.SetClientAssertionJWT.
func (s *JTIStore) Mark(ctx context.Context, jti string, exp time.Time) error {
	if _, err := s.db.ClientAssertionJTI.Delete().
		Where(clientassertionjti.ExpiresAtLTE(s.now())).
		Exec(ctx); err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	if _, err := s.db.ClientAssertionJTI.Create().
		SetJti(jti).
		SetExpiresAt(exp).
		Save(ctx); err != nil {
		if ent.IsConstraintError(err) {
			return fosite.ErrJTIKnown
		}
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}
