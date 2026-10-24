package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/oauthapp"
	"github.com/plexusone/systemforge/identity/systemauth"
)

// Storage implements the Fosite storage interfaces using Ent.
//
// Clients are this package's Client. Authorization codes, tokens, PKCE,
// and revocation are delegated to SystemAuth's storage over the same
// tables, which stores each grant's full request and session, so a code
// exchange keeps the subject, the PKCE challenge, and the redirect URI it
// was issued with, and refresh-token reuse revokes the token family.
type Storage struct {
	db     *ent.Client
	grants *systemauth.EntStorage
}

// NewStorage creates a new Fosite storage backed by Ent.
func NewStorage(db *ent.Client) *Storage {
	return &Storage{db: db, grants: systemauth.NewEntStorage(db)}
}

// hashToken creates a SHA256 signature of a token for secure storage.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// --- ClientManager Interface ---

// GetClient loads an active OAuth client by its client_id, with the
// hashes of its active secrets for client authentication.
func (s *Storage) GetClient(ctx context.Context, clientID string) (fosite.Client, error) {
	app, err := s.db.OAuthApp.Query().
		Where(oauthapp.ClientIDEQ(clientID)).
		Where(oauthapp.ActiveEQ(true)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fosite.ErrNotFound
		}
		return nil, fosite.ErrServerError.WithWrap(err)
	}

	c := &Client{app: app, storage: s}
	if !app.Public {
		hashes, err := systemauth.ActiveClientSecretHashes(ctx, s.db, app.ID)
		if err != nil {
			return nil, fosite.ErrServerError.WithWrap(err)
		}
		c.secretHashes = hashes
	}
	return c, nil
}

// ClientAssertionJWTValid reports fosite.ErrJTIKnown for a
// client-assertion JWT ID that is already used.
func (s *Storage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return s.grants.ClientAssertionJWTValid(ctx, jti)
}

// SetClientAssertionJWT records a client-assertion JWT ID as used until exp.
func (s *Storage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return s.grants.SetClientAssertionJWT(ctx, jti, exp)
}

// --- AuthorizeCodeStorage Interface ---

// CreateAuthorizeCodeSession stores an authorization code with its request.
func (s *Storage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	return s.grants.CreateAuthorizeCodeSession(ctx, code, request)
}

// GetAuthorizeCodeSession restores the request an authorization code was
// issued for. A code already exchanged returns the request with
// fosite.ErrInvalidatedAuthorizeCode, so Fosite revokes its tokens.
func (s *Storage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	return s.grants.GetAuthorizeCodeSession(ctx, code, session)
}

// InvalidateAuthorizeCodeSession marks an authorization code as used.
func (s *Storage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return s.grants.InvalidateAuthorizeCodeSession(ctx, code)
}

// --- AccessTokenStorage Interface ---

// CreateAccessTokenSession stores an access token with its request.
func (s *Storage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.grants.CreateAccessTokenSession(ctx, signature, request)
}

// GetAccessTokenSession restores the request an access token was issued for.
func (s *Storage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.grants.GetAccessTokenSession(ctx, signature, session)
}

// DeleteAccessTokenSession removes an access token session.
func (s *Storage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.grants.DeleteAccessTokenSession(ctx, signature)
}

// --- RefreshTokenStorage Interface ---

// CreateRefreshTokenSession stores a refresh token, on the paired access
// token's row when there is one.
func (s *Storage) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	return s.grants.CreateRefreshTokenSession(ctx, signature, accessSignature, request)
}

// GetRefreshTokenSession restores the request a refresh token was issued
// for. A rotated refresh token returns the request with
// fosite.ErrInactiveToken, so Fosite revokes the whole token family.
func (s *Storage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.grants.GetRefreshTokenSession(ctx, signature, session)
}

// DeleteRefreshTokenSession revokes a refresh token.
func (s *Storage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.grants.DeleteRefreshTokenSession(ctx, signature)
}

// RotateRefreshToken retires the current tokens of a family before Fosite
// stores their replacements.
func (s *Storage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	return s.grants.RotateRefreshToken(ctx, requestID, refreshTokenSignature)
}

// RevokeRefreshToken revokes every token of the family identified by the
// Fosite request ID.
func (s *Storage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.grants.RevokeRefreshToken(ctx, requestID)
}

// RevokeAccessToken revokes every token of the family identified by the
// Fosite request ID.
func (s *Storage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.grants.RevokeAccessToken(ctx, requestID)
}

// --- PKCERequestStorage Interface ---

// CreatePKCERequestSession records a code's PKCE challenge.
func (s *Storage) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.grants.CreatePKCERequestSession(ctx, signature, request)
}

// GetPKCERequestSession restores a code's request with its PKCE challenge.
func (s *Storage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.grants.GetPKCERequestSession(ctx, signature, session)
}

// DeletePKCERequestSession is a no-op: the challenge lives on the
// authorization code, which the code exchange invalidates.
func (s *Storage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.grants.DeletePKCERequestSession(ctx, signature)
}

// --- Helper Functions ---

func scopesToStrings(scopes fosite.Arguments) []string {
	result := make([]string, len(scopes))
	copy(result, scopes)
	return result
}

// Compile-time checks that Storage satisfies the Fosite storage interfaces
// the provider composes; a mismatch otherwise surfaces as a panic in
// compose.Compose.
var (
	_ fosite.Storage                = (*Storage)(nil)
	_ oauth2.CoreStorage            = (*Storage)(nil)
	_ oauth2.TokenRevocationStorage = (*Storage)(nil)
	_ pkce.PKCERequestStorage       = (*Storage)(nil)
)
