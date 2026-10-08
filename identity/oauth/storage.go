package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"

	"github.com/plexusone/systemforge/identity/clientassertion"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/oauthapp"
	"github.com/plexusone/systemforge/identity/ent/oauthauthcode"
	"github.com/plexusone/systemforge/identity/ent/oauthtoken"
)

// Storage implements fosite.Storage interfaces using Ent.
type Storage struct {
	db *ent.Client
}

// NewStorage creates a new Fosite storage backed by Ent.
func NewStorage(db *ent.Client) *Storage {
	return &Storage{db: db}
}

// hashToken creates a SHA256 signature of a token for secure storage.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// --- ClientManager Interface ---

// GetClient loads an OAuth client by its client_id.
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

	return &Client{app: app, storage: s}, nil
}

// --- ClientManager Interface ---

// ClientAssertionJWTValid implements fosite.ClientManager: it reports
// fosite.ErrJTIKnown for a client-assertion JWT ID that is already used.
func (s *Storage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return clientassertion.NewJTIStore(s.db).Valid(ctx, jti)
}

// SetClientAssertionJWT implements fosite.ClientManager: it records a
// client-assertion JWT ID as used until exp.
func (s *Storage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return clientassertion.NewJTIStore(s.db).Mark(ctx, jti, exp)
}

// --- AuthorizeCodeStorage Interface ---

// CreateAuthorizeCodeSession stores an authorization code session.
func (s *Storage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	signature := hashToken(code)
	client := request.GetClient().(*Client)
	session := request.GetSession()

	builder := s.db.OAuthAuthCode.Create().
		SetCodeSignature(signature).
		SetAppID(client.app.ID).
		SetSubject(session.GetSubject()).
		SetRedirectURI(request.GetRequestForm().Get("redirect_uri")).
		SetScopes(scopesToStrings(request.GetGrantedScopes())).
		SetState(request.GetRequestForm().Get("state")).
		SetExpiresAt(time.Now().Add(10 * time.Minute))

	// Store PKCE challenge if present
	if challenge := request.GetRequestForm().Get("code_challenge"); challenge != "" {
		builder.SetCodeChallenge(challenge)
		builder.SetCodeChallengeMethod(request.GetRequestForm().Get("code_challenge_method"))
	}

	// Store nonce for OIDC
	if nonce := request.GetRequestForm().Get("nonce"); nonce != "" {
		builder.SetNonce(nonce)
	}

	_, err := builder.Save(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}

	return nil
}

// GetAuthorizeCodeSession retrieves an authorization code session.
func (s *Storage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	signature := hashToken(code)

	authCode, err := s.db.OAuthAuthCode.Query().
		Where(oauthauthcode.CodeSignatureEQ(signature)).
		WithApp().
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fosite.ErrNotFound
		}
		return nil, fosite.ErrServerError.WithWrap(err)
	}

	if authCode.Used {
		return nil, fosite.ErrInvalidatedAuthorizeCode
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	// Reconstruct the request
	client := &Client{app: authCode.Edges.App, storage: s}
	req := fosite.NewRequest()
	req.SetSession(session)
	req.Client = client
	req.GrantedScope = authCode.Scopes

	return req, nil
}

// InvalidateAuthorizeCodeSession marks an authorization code as used.
func (s *Storage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	signature := hashToken(code)

	_, err := s.db.OAuthAuthCode.Update().
		Where(oauthauthcode.CodeSignatureEQ(signature)).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}

	return nil
}

// --- AccessTokenStorage Interface ---

// CreateAccessTokenSession stores an access token session.
func (s *Storage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	client := request.GetClient().(*Client)
	session := request.GetSession()

	builder := s.db.OAuthToken.Create().
		SetAccessTokenSignature(hashToken(signature)).
		SetAppID(client.app.ID).
		SetScopes(scopesToStrings(request.GetGrantedScopes())).
		SetAccessExpiresAt(session.GetExpiresAt(fosite.AccessToken))
	setFamily(builder, request)

	// Record the subject when present (empty for client_credentials).
	if subject := session.GetSubject(); subject != "" {
		builder.SetSubject(subject)
	}

	_, err := builder.Save(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}

	return nil
}

// GetAccessTokenSession retrieves an access token session.
func (s *Storage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	token, err := s.db.OAuthToken.Query().
		Where(oauthtoken.AccessTokenSignatureEQ(hashToken(signature))).
		WithApp().
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fosite.ErrNotFound
		}
		return nil, fosite.ErrServerError.WithWrap(err)
	}

	if token.Revoked {
		return nil, fosite.ErrInactiveToken
	}

	if time.Now().After(token.AccessExpiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	client := &Client{app: token.Edges.App, storage: s}
	req := fosite.NewRequest()
	req.SetSession(session)
	req.Client = client
	req.GrantedScope = token.Scopes

	return req, nil
}

// DeleteAccessTokenSession removes an access token session.
func (s *Storage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.OAuthToken.Delete().
		Where(oauthtoken.AccessTokenSignatureEQ(hashToken(signature))).
		Exec(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}

// --- RefreshTokenStorage Interface ---

// CreateRefreshTokenSession stores a refresh token session.
//
// When accessSignature names the access token issued alongside it, the
// refresh token is recorded on that token's row; otherwise a new row is
// created for it.
func (s *Storage) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	client := request.GetClient().(*Client)
	session := request.GetSession()

	if accessSignature != "" {
		n, err := s.db.OAuthToken.Update().
			Where(oauthtoken.AccessTokenSignatureEQ(hashToken(accessSignature))).
			SetRefreshTokenSignature(hashToken(signature)).
			SetRefreshExpiresAt(session.GetExpiresAt(fosite.RefreshToken)).
			Save(ctx)
		if err != nil {
			return fosite.ErrServerError.WithWrap(err)
		}
		if n > 0 {
			return nil
		}
	}

	// No paired access token row: generate a unique access token signature
	// for this token pair.
	accessSig := hashToken(uuid.New().String())

	builder := s.db.OAuthToken.Create().
		SetAccessTokenSignature(accessSig).
		SetRefreshTokenSignature(hashToken(signature)).
		SetAppID(client.app.ID).
		SetScopes(scopesToStrings(request.GetGrantedScopes())).
		SetAccessExpiresAt(session.GetExpiresAt(fosite.AccessToken)).
		SetRefreshExpiresAt(session.GetExpiresAt(fosite.RefreshToken))
	setFamily(builder, request)

	if subject := session.GetSubject(); subject != "" {
		builder.SetSubject(subject)
	}

	_, err := builder.Save(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}

	return nil
}

// GetRefreshTokenSession retrieves a refresh token session.
func (s *Storage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	token, err := s.db.OAuthToken.Query().
		Where(oauthtoken.RefreshTokenSignatureEQ(hashToken(signature))).
		WithApp().
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fosite.ErrNotFound
		}
		return nil, fosite.ErrServerError.WithWrap(err)
	}

	if token.Revoked {
		return nil, fosite.ErrInactiveToken
	}

	if token.RefreshExpiresAt != nil && time.Now().After(*token.RefreshExpiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	client := &Client{app: token.Edges.App, storage: s}
	req := fosite.NewRequest()
	req.SetSession(session)
	req.Client = client
	req.GrantedScope = token.Scopes

	return req, nil
}

// DeleteRefreshTokenSession removes a refresh token session.
func (s *Storage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.OAuthToken.Update().
		Where(oauthtoken.RefreshTokenSignatureEQ(hashToken(signature))).
		SetRevoked(true).
		SetRevokedAt(time.Now()).
		SetRevokedReason("deleted").
		Save(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}

// RotateRefreshToken retires the refresh token that was just exchanged, so
// it cannot be used again after rotation.
func (s *Storage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	_, err := s.db.OAuthToken.Update().
		Where(
			oauthtoken.RefreshTokenSignatureEQ(hashToken(refreshTokenSignature)),
			oauthtoken.RevokedEQ(false),
		).
		SetRevoked(true).
		SetRevokedAt(time.Now()).
		SetRevokedReason("rotated").
		Save(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}

// setFamily records the Fosite request ID as the token family, which
// identifies the tokens of one grant across refreshes and is what
// RevokeRefreshToken and RevokeAccessToken revoke.
func setFamily(builder *ent.OAuthTokenCreate, request fosite.Requester) {
	if familyID, err := uuid.Parse(request.GetID()); err == nil {
		builder.SetFamilyID(familyID)
	}
}

// RevokeRefreshToken revokes a refresh token.
func (s *Storage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	// Revoke by family ID to handle rotation
	familyID, err := uuid.Parse(requestID)
	if err != nil {
		return nil // Not a valid family ID, skip
	}

	_, err = s.db.OAuthToken.Update().
		Where(oauthtoken.FamilyIDEQ(familyID)).
		SetRevoked(true).
		SetRevokedAt(time.Now()).
		SetRevokedReason("refresh_rotation").
		Save(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}

// RevokeAccessToken revokes an access token.
func (s *Storage) RevokeAccessToken(ctx context.Context, requestID string) error {
	// For simplicity, we use the same family-based revocation
	return s.RevokeRefreshToken(ctx, requestID)
}

// --- PKCERequestStorage Interface ---

// GetPKCERequestSession gets the PKCE session for a code.
func (s *Storage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.GetAuthorizeCodeSession(ctx, signature, session)
}

// CreatePKCERequestSession creates a PKCE session (same as auth code).
func (s *Storage) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	// PKCE data is stored with the auth code
	return nil
}

// DeletePKCERequestSession deletes a PKCE session.
func (s *Storage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.InvalidateAuthorizeCodeSession(ctx, signature)
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
