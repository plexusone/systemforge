package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principaltoken"
	"github.com/plexusone/systemforge/identity/principal"
)

const (
	// TokenBytes is the number of random bytes for token generation.
	TokenBytes = 32
	// DefaultAccessTTL is the access token lifetime when none is given.
	DefaultAccessTTL = 15 * time.Minute

	revokedRotated  = "rotated"
	revokedReuse    = "refresh token reuse"
	revokedInactive = "principal inactive"
)

var (
	// ErrInvalidAccessToken is returned for an unknown, revoked, or
	// expired access token.
	ErrInvalidAccessToken = errors.New("token: invalid access token")
	// ErrInvalidRefreshToken is returned for an unknown, spent, revoked,
	// or expired refresh token.
	ErrInvalidRefreshToken = errors.New("token: invalid refresh token")
	// ErrRefreshTokenReused is returned when an already-rotated refresh
	// token is presented again; the token family has been revoked.
	ErrRefreshTokenReused = fmt.Errorf("%w: reused, token family revoked", ErrInvalidRefreshToken)
	// ErrDPoPMismatch is returned when a DPoP-bound refresh token is
	// presented without its key.
	ErrDPoPMismatch = errors.New("token: DPoP binding mismatch")
	// ErrScopeNotGranted is returned when a refresh asks for a scope the
	// original grant did not include.
	ErrScopeNotGranted = errors.New("token: scope not in original grant")
)

// DefaultService implements the Service interface.
type DefaultService struct {
	client     *ent.Client
	accessSink accesschange.Sink
}

// Option configures a DefaultService.
type Option func(*DefaultService)

// WithAccessChangeSink announces RevokeAllForPrincipal to sink after it
// commits (ADR-010). The access-change record is written whether or not a
// sink is set.
func WithAccessChangeSink(sink accesschange.Sink) Option {
	return func(s *DefaultService) { s.accessSink = sink }
}

// NewService creates a new TokenService.
func NewService(client *ent.Client, opts ...Option) Service {
	s := &DefaultService{client: client}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Issue issues a new token pair in a new token family.
func (s *DefaultService) Issue(ctx context.Context, input IssueInput) (*IssuedToken, error) {
	var refreshExpiresAt *time.Time
	if input.RefreshTTL > 0 {
		t := time.Now().Add(input.RefreshTTL)
		refreshExpiresAt = &t
	}
	return issue(ctx, s.client, input, uuid.New(), refreshExpiresAt)
}

// issue creates a token pair in family. A refresh token is issued when
// refreshExpiresAt is set.
func issue(ctx context.Context, client *ent.Client, input IssueInput, family uuid.UUID, refreshExpiresAt *time.Time) (*IssuedToken, error) {
	accessToken, accessSig, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	var refreshToken, refreshSig string
	if refreshExpiresAt != nil {
		refreshToken, refreshSig, err = generateToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate refresh token: %w", err)
		}
	}

	accessTTL := input.AccessTTL
	if accessTTL <= 0 {
		accessTTL = DefaultAccessTTL
	}
	accessExpiresAt := time.Now().Add(accessTTL)

	create := client.PrincipalToken.Create().
		SetPrincipalID(input.PrincipalID).
		SetPrincipalType(mapPrincipalType(input.PrincipalType)).
		SetAccessTokenSignature(accessSig).
		SetFamilyID(family).
		SetScopes(input.Scopes).
		SetAudience(input.Audience).
		SetCapabilities(input.Capabilities).
		SetDelegationChain(input.DelegationChain).
		SetAccessExpiresAt(accessExpiresAt)

	if input.IssuedByAppID != nil {
		create.SetIssuedByAppID(*input.IssuedByAppID)
	}
	if refreshSig != "" {
		create.SetRefreshTokenSignature(refreshSig)
		create.SetRefreshExpiresAt(*refreshExpiresAt)
	}
	if input.DPoPJKT != "" {
		create.SetDpopJkt(input.DPoPJKT)
	}
	if input.SessionID != "" {
		create.SetSessionID(input.SessionID)
	}
	if input.ClientIP != "" {
		create.SetClientIP(input.ClientIP)
	}
	if input.UserAgent != "" {
		create.SetUserAgent(input.UserAgent)
	}
	if input.ParentTokenID != nil {
		create.SetParentTokenID(*input.ParentTokenID)
	}

	token, err := create.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	return &IssuedToken{
		Token:        entTokenToModel(token),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTTL.Seconds()),
	}, nil
}

// Refresh rotates a token pair: it spends the presented refresh token and
// issues a new pair in the same family, atomically, so a refresh token
// works once. The new refresh token expires when the family's first one
// did; refreshing never extends a session. Presenting a refresh token that
// was already rotated means it was copied, so the whole family is revoked
// and ErrRefreshTokenReused is returned.
func (s *DefaultService) Refresh(ctx context.Context, input RefreshInput) (*IssuedToken, error) {
	refreshSig := signature(input.RefreshToken)
	var out *IssuedToken
	var reusedFamily, inactiveFamily *uuid.UUID

	err := s.withTx(ctx, func(tx *ent.Tx) error {
		old, err := tx.PrincipalToken.Query().
			Where(principaltoken.RefreshTokenSignatureEQ(refreshSig)).
			Only(ctx)
		if ent.IsNotFound(err) {
			return ErrInvalidRefreshToken
		}
		if err != nil {
			return fmt.Errorf("failed to find token: %w", err)
		}
		if old.Revoked {
			if old.RevokedReason == revokedRotated {
				reusedFamily = &old.FamilyID
			}
			return ErrInvalidRefreshToken
		}
		if old.RefreshExpiresAt == nil || !old.RefreshExpiresAt.After(time.Now()) {
			return ErrInvalidRefreshToken
		}
		if old.DpopJkt != "" && old.DpopJkt != input.DPoPJKT {
			return ErrDPoPMismatch
		}
		active, err := principalActive(ctx, tx.Client(), old.PrincipalID)
		if err != nil {
			return err
		}
		if !active {
			inactiveFamily = &old.FamilyID
			return ErrInvalidRefreshToken
		}

		scopes := old.Scopes
		if len(input.Scopes) > 0 {
			granted := make(map[string]bool, len(old.Scopes))
			for _, sc := range old.Scopes {
				granted[sc] = true
			}
			for _, sc := range input.Scopes {
				if !granted[sc] {
					return fmt.Errorf("%w: %q", ErrScopeNotGranted, sc)
				}
			}
			scopes = input.Scopes
		}

		// Spend the presented token; the condition makes concurrent
		// refreshes with the same token succeed at most once.
		n, err := tx.PrincipalToken.Update().
			Where(principaltoken.ID(old.ID), principaltoken.RevokedEQ(false)).
			SetRevoked(true).
			SetRevokedAt(time.Now()).
			SetRevokedReason(revokedRotated).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to spend refresh token: %w", err)
		}
		if n != 1 {
			return ErrInvalidRefreshToken
		}

		out, err = issue(ctx, tx.Client(), IssueInput{
			PrincipalID:     old.PrincipalID,
			PrincipalType:   principal.Type(old.PrincipalType.String()),
			IssuedByAppID:   old.IssuedByAppID,
			Scopes:          scopes,
			Audience:        old.Audience,
			Capabilities:    old.Capabilities,
			DelegationChain: old.DelegationChain,
			DPoPJKT:         input.DPoPJKT,
			SessionID:       old.SessionID,
			AccessTTL:       old.AccessExpiresAt.Sub(old.CreatedAt),
			ClientIP:        input.ClientIP,
			UserAgent:       input.UserAgent,
			ParentTokenID:   old.ParentTokenID,
		}, old.FamilyID, old.RefreshExpiresAt)
		return err
	})
	if inactiveFamily != nil {
		if rerr := s.revokeFamily(ctx, *inactiveFamily, revokedInactive); rerr != nil {
			return nil, errors.Join(ErrInvalidRefreshToken, rerr)
		}
		return nil, ErrInvalidRefreshToken
	}
	if reusedFamily != nil {
		if rerr := s.revokeFamily(ctx, *reusedFamily, revokedReuse); rerr != nil {
			return nil, errors.Join(ErrRefreshTokenReused, rerr)
		}
		return nil, ErrRefreshTokenReused
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Validate validates an access token and returns the token record.
func (s *DefaultService) Validate(ctx context.Context, accessToken string) (*Token, error) {
	token, err := s.client.PrincipalToken.Query().
		Where(
			principaltoken.AccessTokenSignatureEQ(signature(accessToken)),
			principaltoken.RevokedEQ(false),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrInvalidAccessToken
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find token: %w", err)
	}
	if !token.AccessExpiresAt.After(time.Now()) {
		return nil, ErrInvalidAccessToken
	}
	active, err := principalActive(ctx, s.client, token.PrincipalID)
	if err != nil {
		return nil, err
	}
	if !active {
		if err := s.revokeFamily(ctx, token.FamilyID, revokedInactive); err != nil {
			return nil, errors.Join(ErrInvalidAccessToken, err)
		}
		return nil, ErrInvalidAccessToken
	}
	if err := s.client.PrincipalToken.UpdateOne(token).SetLastUsedAt(time.Now()).Exec(ctx); err != nil {
		return nil, fmt.Errorf("failed to record token use: %w", err)
	}
	return entTokenToModel(token), nil
}

// Revoke revokes a token.
func (s *DefaultService) Revoke(ctx context.Context, tokenID uuid.UUID, revokeFamily bool, reason string) error {
	now := time.Now()

	if revokeFamily {
		// Get the token to find its family ID
		token, err := s.client.PrincipalToken.Get(ctx, tokenID)
		if err != nil {
			return fmt.Errorf("failed to get token: %w", err)
		}

		// Revoke all tokens in the family
		_, err = s.client.PrincipalToken.Update().
			Where(principaltoken.FamilyIDEQ(token.FamilyID)).
			SetRevoked(true).
			SetRevokedAt(now).
			SetRevokedReason(reason).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to revoke token family: %w", err)
		}
	} else {
		// Revoke single token
		_, err := s.client.PrincipalToken.UpdateOneID(tokenID).
			SetRevoked(true).
			SetRevokedAt(now).
			SetRevokedReason(reason).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to revoke token: %w", err)
		}
	}

	return nil
}

// RevokeBySignature revokes a token by its access token signature.
func (s *DefaultService) RevokeBySignature(ctx context.Context, accessTokenSignature string, revokeFamily bool, reason string) error {
	token, err := s.client.PrincipalToken.Query().
		Where(principaltoken.AccessTokenSignatureEQ(accessTokenSignature)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return fmt.Errorf("token not found")
		}
		return fmt.Errorf("failed to find token: %w", err)
	}

	return s.Revoke(ctx, token.ID, revokeFamily, reason)
}

// GetCapabilitiesForType returns the default capabilities for a principal type.
func (s *DefaultService) GetCapabilitiesForType(principalType principal.Type) Capabilities {
	caps := principal.DefaultCapabilitiesForType(principalType)
	return Capabilities{
		CanAccessUI:       caps.CanAccessUI,
		CanManageProfile:  caps.CanManageProfile,
		CanActOnBehalf:    caps.CanActOnBehalf,
		CanDelegate:       caps.CanDelegate,
		RequiresApproval:  caps.RequiresApproval,
		CanBypassRLS:      caps.CanBypassRLS,
		CanRequestOffline: caps.CanRequestOffline,
	}
}

// ListForPrincipal lists all active tokens for a principal.
func (s *DefaultService) ListForPrincipal(ctx context.Context, principalID uuid.UUID) ([]*Token, error) {
	tokens, err := s.client.PrincipalToken.Query().
		Where(
			principaltoken.PrincipalIDEQ(principalID),
			principaltoken.RevokedEQ(false),
			principaltoken.AccessExpiresAtGT(time.Now()),
		).
		Order(ent.Desc(principaltoken.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}

	result := make([]*Token, len(tokens))
	for i, t := range tokens {
		result[i] = entTokenToModel(t)
	}
	return result, nil
}

// RevokeAllForPrincipal revokes all tokens for a principal.
func (s *DefaultService) RevokeAllForPrincipal(ctx context.Context, principalID uuid.UUID, reason string) error {
	now := time.Now()
	var change accesschange.Change
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		if _, err := tx.PrincipalToken.Update().
			Where(
				principaltoken.PrincipalIDEQ(principalID),
				principaltoken.RevokedEQ(false),
			).
			SetRevoked(true).
			SetRevokedAt(now).
			SetRevokedReason(reason).
			Save(ctx); err != nil {
			return fmt.Errorf("failed to revoke tokens: %w", err)
		}
		// Access tokens already issued stop being honored at once (ADR-010).
		var err error
		change, err = accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: principalID, Reason: accesschange.SessionsRevoked})
		return err
	})
	if err != nil {
		return err
	}
	accesschange.Publish(s.accessSink, change)
	return nil
}

// Helper functions

func (s *DefaultService) revokeFamily(ctx context.Context, family uuid.UUID, reason string) error {
	_, err := s.client.PrincipalToken.Update().
		Where(principaltoken.FamilyIDEQ(family), principaltoken.RevokedEQ(false)).
		SetRevoked(true).
		SetRevokedAt(time.Now()).
		SetRevokedReason(reason).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to revoke token family: %w", err)
	}
	return nil
}

func (s *DefaultService) withTx(ctx context.Context, fn func(*ent.Tx) error) error {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil {
			return errors.Join(err, fmt.Errorf("rollback: %w", rerr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}
	return nil
}

// principalActive reports whether a token's principal exists and is
// active; tokens of a deactivated or deleted principal are not honored.
func principalActive(ctx context.Context, client *ent.Client, id uuid.UUID) (bool, error) {
	ok, err := client.Principal.Query().Where(entprincipal.ID(id), entprincipal.Active(true)).Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check principal: %w", err)
	}
	return ok, nil
}

// signature is the stored form of a token: its hex SHA-256.
func signature(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

func generateToken() (plainToken, sig string, err error) {
	bytes := make([]byte, TokenBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	plainToken = base64.RawURLEncoding.EncodeToString(bytes)
	return plainToken, signature(plainToken), nil
}

func entTokenToModel(t *ent.PrincipalToken) *Token {
	return &Token{
		ID:               t.ID,
		PrincipalID:      t.PrincipalID,
		PrincipalType:    principal.Type(t.PrincipalType.String()),
		IssuedByAppID:    t.IssuedByAppID,
		FamilyID:         t.FamilyID,
		ParentTokenID:    t.ParentTokenID,
		Scopes:           t.Scopes,
		Audience:         t.Audience,
		Capabilities:     t.Capabilities,
		DelegationChain:  t.DelegationChain,
		DPoPJKT:          t.DpopJkt,
		SessionID:        t.SessionID,
		AccessExpiresAt:  t.AccessExpiresAt,
		RefreshExpiresAt: t.RefreshExpiresAt,
		Revoked:          t.Revoked,
		RevokedAt:        t.RevokedAt,
		RevokedReason:    t.RevokedReason,
		ClientIP:         t.ClientIP,
		UserAgent:        t.UserAgent,
		LastUsedAt:       t.LastUsedAt,
		CreatedAt:        t.CreatedAt,
	}
}

func mapPrincipalType(t principal.Type) principaltoken.PrincipalType {
	switch t {
	case principal.TypeHuman:
		return principaltoken.PrincipalTypeHuman
	case principal.TypeApplication:
		return principaltoken.PrincipalTypeApplication
	case principal.TypeAgent:
		return principaltoken.PrincipalTypeAgent
	case principal.TypeService:
		return principaltoken.PrincipalTypeService
	default:
		return principaltoken.PrincipalTypeHuman
	}
}
