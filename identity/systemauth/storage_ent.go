package systemauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"golang.org/x/crypto/argon2"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/oauthapp"
	"github.com/plexusone/systemforge/identity/ent/oauthappsecret"
	"github.com/plexusone/systemforge/identity/ent/oauthauthcode"
	"github.com/plexusone/systemforge/identity/ent/oauthtoken"
	userEnt "github.com/plexusone/systemforge/identity/ent/user"
)

// ownerIDContextKey is used to pass owner ID through context.
type ownerIDContextKey struct{}

// ContextWithOwnerID adds an owner ID to the context.
func ContextWithOwnerID(ctx context.Context, ownerID uuid.UUID) context.Context {
	return context.WithValue(ctx, ownerIDContextKey{}, ownerID)
}

// EntStorage implements Storage using Ent ORM.
type EntStorage struct {
	db             *ent.Client
	defaultOwnerID uuid.UUID
}

// EntStorageOption configures EntStorage.
type EntStorageOption func(*EntStorage)

// WithDefaultOwner sets the default owner ID for new clients.
// This is used when creating clients without an explicit owner context.
func WithDefaultOwner(ownerID uuid.UUID) EntStorageOption {
	return func(s *EntStorage) {
		s.defaultOwnerID = ownerID
	}
}

// NewEntStorage creates a new Ent-backed storage.
func NewEntStorage(db *ent.Client, opts ...EntStorageOption) *EntStorage {
	s := &EntStorage{db: db}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// --- User Management for Federation ---
// Note: These methods work with the systemauth User type for federation sync.
// The Ent User entity will need federation fields added for full support.

// CreateUser creates a new user from federation sync.
func (s *EntStorage) CreateUser(ctx context.Context, user *User) error {
	// Use the Ent User entity
	_, err := s.db.User.Create().
		SetID(user.ID).
		SetEmail(user.Email).
		SetName(user.Name).
		SetActive(user.Active).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return ErrUserExists
		}
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// GetUserByID retrieves a user by ID.
func (s *EntStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	entUser, err := s.db.User.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return s.entUserToUser(entUser), nil
}

// GetUserByEmail retrieves a user by email.
func (s *EntStorage) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	entUser, err := s.db.User.Query().
		Where(userEnt.EmailEQ(email)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return s.entUserToUser(entUser), nil
}

// GetUserByFederationID retrieves a user by their federation ID.
func (s *EntStorage) GetUserByFederationID(ctx context.Context, federationID uuid.UUID) (*User, error) {
	entUser, err := s.db.User.Query().
		Where(userEnt.FederationIDEQ(federationID)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by federation ID: %w", err)
	}
	return s.entUserToUser(entUser), nil
}

// UpdateUser updates an existing user.
func (s *EntStorage) UpdateUser(ctx context.Context, user *User) error {
	_, err := s.db.User.UpdateOneID(user.ID).
		SetEmail(user.Email).
		SetName(user.Name).
		SetActive(user.Active).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

// DeleteUser deletes a user.
func (s *EntStorage) DeleteUser(ctx context.Context, id uuid.UUID) error {
	err := s.db.User.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

// entUserToUser converts an Ent User to a systemauth User.
func (s *EntStorage) entUserToUser(entUser *ent.User) *User {
	user := &User{
		ID:           entUser.ID,
		Email:        entUser.Email,
		Name:         entUser.Name,
		Active:       entUser.Active,
		Federated:    entUser.FederationID != nil,
		FederationID: entUser.FederationID,
	}
	return user
}

// Ensure EntStorage implements Storage.
var _ Storage = (*EntStorage)(nil)

// hashToken creates a SHA256 signature of a token for secure storage.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// --- ClientManager Interface ---

// GetClient loads an OAuth client by its client_id.
func (s *EntStorage) GetClient(ctx context.Context, clientID string) (fosite.Client, error) {
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

	return s.entAppToClient(app), nil
}

// CreateClient creates a new OAuth client.
func (s *EntStorage) CreateClient(ctx context.Context, client *Client) error {
	// Determine app type from client type
	appType := oauthapp.AppTypeWeb
	if client.IsPublic() {
		appType = oauthapp.AppTypeSpa
	}

	// Create the app
	builder := s.db.OAuthApp.Create().
		SetClientID(client.ID).
		SetName(client.Name).
		SetAppType(appType).
		SetRedirectUris(client.RedirectURIs).
		SetAllowedScopes(client.Scopes).
		SetAllowedGrants(client.GrantTypes).
		SetAllowedResponseTypes(client.ResponseTypes).
		SetPublic(client.IsPublic())

	if client.Description != "" {
		builder.SetDescription(client.Description)
	}

	// Set token TTLs if custom
	if client.AccessTokenLifetime != nil {
		builder.SetAccessTokenTTL(int(client.AccessTokenLifetime.Seconds()))
	}
	if client.RefreshTokenLifetime != nil {
		builder.SetRefreshTokenTTL(int(client.RefreshTokenLifetime.Seconds()))
	}

	// Set owner ID - use default if configured, otherwise use nil UUID
	ownerID := s.defaultOwnerID
	if ownerID == uuid.Nil {
		// Check context for owner ID
		if ctxOwnerID, ok := ctx.Value(ownerIDContextKey{}).(uuid.UUID); ok {
			ownerID = ctxOwnerID
		}
	}
	builder.SetOwnerID(ownerID)

	app, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return fmt.Errorf("%w: %s", ErrClientExists, client.ID)
		}
		return fmt.Errorf("failed to create client: %w", err)
	}

	// If there's a secret, create a secret entry
	if client.SecretHash != "" {
		_, err = s.db.OAuthAppSecret.Create().
			SetAppID(app.ID).
			SetSecretHash(client.SecretHash).
			SetSecretPrefix(client.ID[:min(8, len(client.ID))]).
			Save(ctx)
		if err != nil {
			// Clean up the app if secret creation fails
			_ = s.db.OAuthApp.DeleteOne(app).Exec(ctx)
			return fmt.Errorf("failed to create client secret: %w", err)
		}
	}

	return nil
}

// GetClientByID retrieves a client by ID.
func (s *EntStorage) GetClientByID(ctx context.Context, id string) (*Client, error) {
	app, err := s.db.OAuthApp.Query().
		Where(oauthapp.ClientIDEQ(id)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrClientNotFound
		}
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return s.entAppToClient(app), nil
}

// UpdateClient updates an existing client.
func (s *EntStorage) UpdateClient(ctx context.Context, client *Client) error {
	app, err := s.db.OAuthApp.Query().
		Where(oauthapp.ClientIDEQ(client.ID)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrClientNotFound
		}
		return fmt.Errorf("failed to find client: %w", err)
	}

	builder := s.db.OAuthApp.UpdateOne(app).
		SetName(client.Name).
		SetRedirectUris(client.RedirectURIs).
		SetAllowedScopes(client.Scopes).
		SetAllowedGrants(client.GrantTypes).
		SetAllowedResponseTypes(client.ResponseTypes)

	if client.Description != "" {
		builder.SetDescription(client.Description)
	}

	if client.AccessTokenLifetime != nil {
		builder.SetAccessTokenTTL(int(client.AccessTokenLifetime.Seconds()))
	}
	if client.RefreshTokenLifetime != nil {
		builder.SetRefreshTokenTTL(int(client.RefreshTokenLifetime.Seconds()))
	}

	_, err = builder.Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to update client: %w", err)
	}

	return nil
}

// DeleteClient deletes a client.
func (s *EntStorage) DeleteClient(ctx context.Context, id string) error {
	app, err := s.db.OAuthApp.Query().
		Where(oauthapp.ClientIDEQ(id)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrClientNotFound
		}
		return fmt.Errorf("failed to find client: %w", err)
	}

	// Soft delete by marking inactive
	_, err = s.db.OAuthApp.UpdateOne(app).
		SetActive(false).
		SetRevokedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}

	return nil
}

// ListClients returns all clients.
func (s *EntStorage) ListClients(ctx context.Context) ([]*Client, error) {
	apps, err := s.db.OAuthApp.Query().
		Where(oauthapp.ActiveEQ(true)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list clients: %w", err)
	}

	clients := make([]*Client, len(apps))
	for i, app := range apps {
		clients[i] = s.entAppToClient(app)
	}

	return clients, nil
}

// --- Authorization Code Storage ---

// CreateAuthorizeCodeSession stores an authorization code session.
func (s *EntStorage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	signature := hashToken(code)
	client := request.GetClient()
	session := request.GetSession()

	// Get the app by client ID
	app, err := s.db.OAuthApp.Query().
		Where(oauthapp.ClientIDEQ(client.GetID())).
		First(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}

	// Serialize the request (including the session) for later reconstruction
	requestData, err := s.serializeRequest(request)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}

	subject := sessionSubject(session)
	builder := s.db.OAuthAuthCode.Create().
		SetCodeSignature(signature).
		SetAppID(app.ID).
		SetSubject(subject).
		SetRedirectURI(request.GetRequestForm().Get("redirect_uri")).
		SetScopes(scopesToStrings(request.GetGrantedScopes())).
		SetState(request.GetRequestForm().Get("state")).
		SetRequestData(requestData).
		SetExpiresAt(codeExpiry(session))

	userID, err := s.legacyUserID(ctx, subject)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	builder.SetNillableUserID(userID)

	// Store PKCE challenge if present
	if challenge := request.GetRequestForm().Get("code_challenge"); challenge != "" {
		builder.SetCodeChallenge(challenge)
		builder.SetCodeChallengeMethod(request.GetRequestForm().Get("code_challenge_method"))
	}

	// Store nonce for OIDC
	if nonce := request.GetRequestForm().Get("nonce"); nonce != "" {
		builder.SetNonce(nonce)
	}

	_, err = builder.Save(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}

	return nil
}

// codeExpiry returns the authorization code expiry recorded in session, or
// ten minutes from now when the session carries none.
func codeExpiry(session fosite.Session) time.Time {
	if session != nil {
		if exp := session.GetExpiresAt(fosite.AuthorizeCode); !exp.IsZero() {
			return exp
		}
	}
	return time.Now().Add(10 * time.Minute)
}

// GetAuthorizeCodeSession retrieves an authorization code session. A code
// that was already exchanged returns the request together with
// fosite.ErrInvalidatedAuthorizeCode so Fosite can revoke the tokens issued
// from it (authorization code replay).
func (s *EntStorage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
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

	req := fosite.NewRequest()
	req.Client = s.entAppToClient(authCode.Edges.App)
	req.GrantedScope = authCode.Scopes
	req.RequestedAt = authCode.CreatedAt
	if err := s.restoreRequest(authCode.RequestData, req, session); err != nil {
		return nil, fosite.ErrServerError.WithWrap(err)
	}

	if authCode.Used {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	return req, nil
}

// InvalidateAuthorizeCodeSession marks an authorization code as used.
func (s *EntStorage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
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

// --- Access Token Storage ---

// CreateAccessTokenSession stores an access token session.
func (s *EntStorage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	builder, err := s.tokenBuilder(ctx, request)
	if err != nil {
		return err
	}
	builder.SetAccessTokenSignature(hashToken(signature))

	if _, err := builder.Save(ctx); err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}

// tokenBuilder prepares a token row for request: app, subject, scopes,
// expiries, token family and the serialized request with its session.
func (s *EntStorage) tokenBuilder(ctx context.Context, request fosite.Requester) (*ent.OAuthTokenCreate, error) {
	session := request.GetSession()

	app, err := s.db.OAuthApp.Query().
		Where(oauthapp.ClientIDEQ(request.GetClient().GetID())).
		First(ctx)
	if err != nil {
		return nil, fosite.ErrServerError.WithWrap(err)
	}

	requestData, err := s.serializeRequest(request)
	if err != nil {
		return nil, fosite.ErrServerError.WithWrap(err)
	}

	subject := sessionSubject(session)
	builder := s.db.OAuthToken.Create().
		SetAppID(app.ID).
		SetSubject(subject).
		SetScopes(scopesToStrings(request.GetGrantedScopes())).
		SetAudience(scopesToStrings(request.GetGrantedAudience())).
		SetAccessExpiresAt(session.GetExpiresAt(fosite.AccessToken)).
		SetRequestData(requestData)

	userID, err := s.legacyUserID(ctx, subject)
	if err != nil {
		return nil, fosite.ErrServerError.WithWrap(err)
	}
	builder.SetNillableUserID(userID)

	// The Fosite request ID identifies the token family across rotations.
	if familyID, err := uuid.Parse(request.GetID()); err == nil {
		builder.SetFamilyID(familyID)
	}
	return builder, nil
}

// legacyUserID returns subject as a User ID when a legacy User row with that
// ID exists, so the optional user edge is populated for User-based
// deployments. Principal-based subjects return nil.
func (s *EntStorage) legacyUserID(ctx context.Context, subject string) (*uuid.UUID, error) {
	id, err := uuid.Parse(subject)
	if err != nil {
		return nil, nil
	}
	exists, err := s.db.User.Query().Where(userEnt.IDEQ(id)).Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking user: %w", err)
	}
	if !exists {
		return nil, nil
	}
	return &id, nil
}

// tokenRequest rebuilds the Fosite request stored with a token row.
func (s *EntStorage) tokenRequest(token *ent.OAuthToken, session fosite.Session) (*fosite.Request, error) {
	req := fosite.NewRequest()
	req.Client = s.entAppToClient(token.Edges.App)
	req.GrantedScope = token.Scopes
	req.GrantedAudience = token.Audience
	req.RequestedAt = token.CreatedAt
	req.ID = token.FamilyID.String()
	if err := s.restoreRequest(token.RequestData, req, session); err != nil {
		return nil, err
	}
	return req, nil
}

// GetAccessTokenSession retrieves an access token session.
func (s *EntStorage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
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

	req, err := s.tokenRequest(token, session)
	if err != nil {
		return nil, fosite.ErrServerError.WithWrap(err)
	}
	return req, nil
}

// DeleteAccessTokenSession removes an access token session. A row that
// also carries a refresh token is marked revoked instead, so the refresh
// token's reuse can still be detected.
func (s *EntStorage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	sig := hashToken(signature)
	if _, err := s.db.OAuthToken.Delete().
		Where(oauthtoken.AccessTokenSignatureEQ(sig), oauthtoken.RefreshTokenSignatureIsNil()).
		Exec(ctx); err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	_, err := s.db.OAuthToken.Update().
		Where(oauthtoken.AccessTokenSignatureEQ(sig)).
		SetRevoked(true).
		SetRevokedAt(time.Now()).
		SetRevokedReason("deleted").
		Save(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}

// --- Refresh Token Storage ---

// CreateRefreshTokenSession stores a refresh token session. Fosite creates
// the paired access token first; the refresh token is attached to that row
// so revoking either revokes both.
func (s *EntStorage) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	refreshSig := hashToken(signature)
	refreshExp := request.GetSession().GetExpiresAt(fosite.RefreshToken)

	if accessSignature != "" {
		update := s.db.OAuthToken.Update().
			Where(oauthtoken.AccessTokenSignatureEQ(hashToken(accessSignature))).
			SetRefreshTokenSignature(refreshSig)
		if !refreshExp.IsZero() {
			update.SetRefreshExpiresAt(refreshExp)
		}
		n, err := update.Save(ctx)
		if err != nil {
			return fosite.ErrServerError.WithWrap(err)
		}
		if n > 0 {
			return nil
		}
	}

	builder, err := s.tokenBuilder(ctx, request)
	if err != nil {
		return err
	}
	accessKey := accessSignature
	if accessKey == "" {
		// The access token signature column is required and unique.
		accessKey = "refresh-only:" + signature
	}
	builder.SetAccessTokenSignature(hashToken(accessKey)).
		SetRefreshTokenSignature(refreshSig)
	if !refreshExp.IsZero() {
		builder.SetRefreshExpiresAt(refreshExp)
	}
	if _, err := builder.Save(ctx); err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}

// GetRefreshTokenSession retrieves a refresh token session. A revoked
// (rotated) refresh token returns the request together with
// fosite.ErrInactiveToken so Fosite detects reuse and revokes the whole
// token family.
func (s *EntStorage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
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

	req, err := s.tokenRequest(token, session)
	if err != nil {
		return nil, fosite.ErrServerError.WithWrap(err)
	}

	if token.Revoked {
		return req, fosite.ErrInactiveToken
	}

	if token.RefreshExpiresAt != nil && time.Now().After(*token.RefreshExpiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	return req, nil
}

// DeleteRefreshTokenSession removes a refresh token session.
func (s *EntStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.OAuthToken.Update().
		Where(oauthtoken.RefreshTokenSignatureEQ(hashToken(signature))).
		SetRevoked(true).
		SetRevokedAt(time.Now()).
		SetRevokedReason("deleted").
		Save(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}

// RevokeRefreshToken revokes every token of the family identified by the
// Fosite request ID.
func (s *EntStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.revokeFamily(ctx, requestID, "revoked")
}

// RevokeAccessToken revokes every token of the family identified by the
// Fosite request ID. Access and refresh tokens share rows, so this is the
// same operation as RevokeRefreshToken.
func (s *EntStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.revokeFamily(ctx, requestID, "revoked")
}

// RotateRefreshToken retires the current tokens of the family before Fosite
// stores their replacements. Retired rows stay (revoked) so that reuse of
// an old refresh token is detected.
func (s *EntStorage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	return s.revokeFamily(ctx, requestID, "rotated")
}

func (s *EntStorage) revokeFamily(ctx context.Context, requestID, reason string) error {
	familyID, err := uuid.Parse(requestID)
	if err != nil {
		// Fosite request IDs are UUIDs; anything else has no stored family.
		return nil
	}
	_, err = s.db.OAuthToken.Update().
		Where(oauthtoken.FamilyIDEQ(familyID), oauthtoken.RevokedEQ(false)).
		SetRevoked(true).
		SetRevokedAt(time.Now()).
		SetRevokedReason(reason).
		Save(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}

// RevokeSubjectTokens implements SubjectTokenRevoker.
func (s *EntStorage) RevokeSubjectTokens(ctx context.Context, subject string) error {
	if subject == "" {
		return nil
	}
	_, err := s.db.OAuthToken.Update().
		Where(oauthtoken.SubjectEQ(subject), oauthtoken.RevokedEQ(false)).
		SetRevoked(true).
		SetRevokedAt(time.Now()).
		SetRevokedReason("logout").
		Save(ctx)
	if err != nil {
		return fmt.Errorf("revoking tokens for subject: %w", err)
	}
	return nil
}

// --- PKCE Storage ---

// CreatePKCERequestSession records the PKCE challenge on the authorization
// code row (Fosite stores the code first and strips the challenge from the
// request it hands to CreateAuthorizeCodeSession).
func (s *EntStorage) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	form := requester.GetRequestForm()
	challenge := form.Get("code_challenge")
	if challenge == "" {
		return nil
	}
	method := form.Get("code_challenge_method")
	if method == "" {
		method = "plain"
	}
	n, err := s.db.OAuthAuthCode.Update().
		Where(oauthauthcode.CodeSignatureEQ(hashToken(signature))).
		SetCodeChallenge(challenge).
		SetCodeChallengeMethod(method).
		Save(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	if n == 0 {
		return fosite.ErrServerError.WithHint("PKCE session has no matching authorization code.")
	}
	return nil
}

// GetPKCERequestSession gets the PKCE session for a code: the stored
// authorization request with the code challenge restored to its form.
func (s *EntStorage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	authCode, err := s.db.OAuthAuthCode.Query().
		Where(oauthauthcode.CodeSignatureEQ(hashToken(signature))).
		WithApp().
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fosite.ErrNotFound
		}
		return nil, fosite.ErrServerError.WithWrap(err)
	}
	req := fosite.NewRequest()
	req.Client = s.entAppToClient(authCode.Edges.App)
	if err := s.restoreRequest(authCode.RequestData, req, session); err != nil {
		return nil, fosite.ErrServerError.WithWrap(err)
	}
	if authCode.CodeChallenge != "" {
		req.Form.Set("code_challenge", authCode.CodeChallenge)
		req.Form.Set("code_challenge_method", authCode.CodeChallengeMethod)
	}
	return req, nil
}

// DeletePKCERequestSession is a no-op: the PKCE data lives on the
// authorization code row, which the authorization code handler invalidates
// once the exchange completes. Invalidating it here would make the code
// look replayed to the authorization code handler.
func (s *EntStorage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return nil
}

// --- OpenID Connect Sessions ---

// oidcCodeKey keys the OIDC session row for a raw authorization code. It is
// stored in the authorization code table under a distinct prefix.
func oidcCodeKey(authorizeCode string) string {
	return "oidc:" + hashToken(authorizeCode)
}

// CreateOpenIDConnectSession stores the OIDC session for an authorization code.
func (s *EntStorage) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	app, err := s.db.OAuthApp.Query().
		Where(oauthapp.ClientIDEQ(requester.GetClient().GetID())).
		First(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	requestData, err := s.serializeRequest(requester)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	_, err = s.db.OAuthAuthCode.Create().
		SetCodeSignature(oidcCodeKey(authorizeCode)).
		SetAppID(app.ID).
		SetSubject(sessionSubject(requester.GetSession())).
		SetRedirectURI(requester.GetRequestForm().Get("redirect_uri")).
		SetScopes(scopesToStrings(requester.GetGrantedScopes())).
		SetRequestData(requestData).
		SetExpiresAt(codeExpiry(requester.GetSession())).
		Save(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}

// GetOpenIDConnectSession returns the OIDC session for an authorization code.
func (s *EntStorage) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	row, err := s.db.OAuthAuthCode.Query().
		Where(oauthauthcode.CodeSignatureEQ(oidcCodeKey(authorizeCode))).
		WithApp().
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, openid.ErrNoSessionFound
		}
		return nil, fosite.ErrServerError.WithWrap(err)
	}
	req := fosite.NewRequest()
	req.Client = s.entAppToClient(row.Edges.App)
	req.GrantedScope = row.Scopes
	req.RequestedAt = row.CreatedAt
	if err := s.restoreRequest(row.RequestData, req, &Session{}); err != nil {
		return nil, fosite.ErrServerError.WithWrap(err)
	}
	return req, nil
}

// DeleteOpenIDConnectSession removes the OIDC session for an authorization code.
func (s *EntStorage) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	_, err := s.db.OAuthAuthCode.Delete().
		Where(oauthauthcode.CodeSignatureEQ(oidcCodeKey(authorizeCode))).
		Exec(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}

// --- Client Assertion JWT Tracking ---

// ClientAssertionJWTValid checks if a JWT ID has been used.
func (s *EntStorage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	// Check if JTI exists and is not expired
	// For simplicity, we use the auth code table to track JTIs
	// In production, you might want a dedicated table
	exists, err := s.db.OAuthAuthCode.Query().
		Where(oauthauthcode.CodeSignatureEQ("jti:" + jti)).
		Where(oauthauthcode.ExpiresAtGT(time.Now())).
		Exist(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	if exists {
		return fosite.ErrJTIKnown
	}
	return nil
}

// SetClientAssertionJWT marks a JWT ID as used.
func (s *EntStorage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	_, err := s.db.OAuthAuthCode.Create().
		SetCodeSignature("jti:" + jti).
		SetAppID(uuid.Nil). // Placeholder
		SetUserID(uuid.Nil).
		SetRedirectURI("").
		SetExpiresAt(exp).
		Save(ctx)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	return nil
}

// --- Helper Functions ---

// entAppToClient converts an Ent OAuthApp to a systemauth Client.
func (s *EntStorage) entAppToClient(app *ent.OAuthApp) *Client {
	clientType := ClientTypeConfidential
	if app.Public {
		clientType = ClientTypePublic
	}

	client := &Client{
		ID:            app.ClientID,
		Type:          clientType,
		Name:          app.Name,
		Description:   app.Description,
		RedirectURIs:  app.RedirectUris,
		GrantTypes:    app.AllowedGrants,
		ResponseTypes: app.AllowedResponseTypes,
		Scopes:        app.AllowedScopes,
		CreatedAt:     app.CreatedAt,
		UpdatedAt:     app.UpdatedAt,
	}

	// Convert TTLs to durations
	if app.AccessTokenTTL > 0 {
		d := time.Duration(app.AccessTokenTTL) * time.Second
		client.AccessTokenLifetime = &d
	}
	if app.RefreshTokenTTL > 0 {
		d := time.Duration(app.RefreshTokenTTL) * time.Second
		client.RefreshTokenLifetime = &d
	}

	return client
}

// storedRequestData is the serialized form of a Fosite request.
type storedRequestData struct {
	ID                string              `json:"id,omitempty"`
	RequestedAt       time.Time           `json:"requested_at"`
	GrantedScopes     []string            `json:"granted_scopes"`
	RequestedScope    []string            `json:"requested_scope"`
	RequestedAudience []string            `json:"requested_audience,omitempty"`
	GrantedAudience   []string            `json:"granted_audience,omitempty"`
	Form              map[string][]string `json:"form"`
	Session           json.RawMessage     `json:"session,omitempty"`
}

// serializeRequest serializes a Fosite request, including its session, for
// storage.
func (s *EntStorage) serializeRequest(request fosite.Requester) (string, error) {
	data := storedRequestData{
		ID:                request.GetID(),
		RequestedAt:       request.GetRequestedAt(),
		GrantedScopes:     scopesToStrings(request.GetGrantedScopes()),
		RequestedScope:    scopesToStrings(request.GetRequestedScopes()),
		RequestedAudience: scopesToStrings(request.GetRequestedAudience()),
		GrantedAudience:   scopesToStrings(request.GetGrantedAudience()),
		Form:              request.GetRequestForm(),
	}
	if sess := request.GetSession(); sess != nil {
		raw, err := json.Marshal(sess)
		if err != nil {
			return "", fmt.Errorf("serializing session: %w", err)
		}
		data.Session = raw
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// restoreRequest restores the serialized request data into req and
// hydrates session (when non-nil) with the stored session.
func (s *EntStorage) restoreRequest(data string, req *fosite.Request, session fosite.Session) error {
	if session != nil {
		req.SetSession(session)
	}
	if data == "" {
		return nil
	}
	var stored storedRequestData
	if err := json.Unmarshal([]byte(data), &stored); err != nil {
		return fmt.Errorf("decoding stored request: %w", err)
	}
	if stored.ID != "" {
		req.ID = stored.ID
	}
	if !stored.RequestedAt.IsZero() {
		req.RequestedAt = stored.RequestedAt
	}
	req.RequestedScope = stored.RequestedScope
	if len(stored.GrantedScopes) > 0 {
		req.GrantedScope = stored.GrantedScopes
	}
	req.RequestedAudience = stored.RequestedAudience
	if len(stored.GrantedAudience) > 0 {
		req.GrantedAudience = stored.GrantedAudience
	}
	for k, vals := range stored.Form {
		for _, v := range vals {
			req.Form.Add(k, v)
		}
	}
	if session != nil && len(stored.Session) > 0 && string(stored.Session) != "null" {
		if err := json.Unmarshal(stored.Session, session); err != nil {
			return fmt.Errorf("decoding stored session: %w", err)
		}
	}
	return nil
}

func scopesToStrings(scopes fosite.Arguments) []string {
	result := make([]string, len(scopes))
	copy(result, scopes)
	return result
}

// --- Argon2id Secret Validation ---

// ValidateSecretArgon2id validates a client secret using Argon2id.
func (s *EntStorage) ValidateSecretArgon2id(ctx context.Context, clientID, secret string) error {
	// Get the app
	app, err := s.db.OAuthApp.Query().
		Where(oauthapp.ClientIDEQ(clientID)).
		Where(oauthapp.ActiveEQ(true)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return fosite.ErrInvalidClient
		}
		return fosite.ErrServerError.WithWrap(err)
	}

	// Public clients don't have secrets
	if app.Public {
		return nil
	}

	// Find active secrets for this app
	secrets, err := s.db.OAuthAppSecret.Query().
		Where(
			oauthappsecret.AppIDEQ(app.ID),
			oauthappsecret.RevokedEQ(false),
		).
		All(ctx)
	if err != nil {
		return fosite.ErrInvalidClient.WithWrap(err)
	}

	// Try each secret
	for _, sec := range secrets {
		if verifyArgon2id(secret, sec.SecretHash) {
			// Update last used timestamp
			_, _ = s.db.OAuthAppSecret.UpdateOneID(sec.ID).
				SetLastUsedAt(time.Now()).
				Save(ctx)
			return nil
		}
	}

	return fosite.ErrInvalidClient.WithDescription("invalid client secret")
}

// verifyArgon2id verifies a password against an Argon2id hash.
// The hash format is: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func verifyArgon2id(password, encodedHash string) bool {
	params, salt, hash, err := decodeArgon2idHash(encodedHash)
	if err != nil {
		return false
	}

	computed := argon2.IDKey(
		[]byte(password),
		salt,
		params.time,
		params.memory,
		params.parallelism,
		uint32(len(hash)), //nolint:gosec // G115: hash length is bounded
	)

	return subtle.ConstantTimeCompare(computed, hash) == 1
}

// argon2idParams holds Argon2id parameters.
type argon2idParams struct {
	memory      uint32
	time        uint32
	parallelism uint8
}

// decodeArgon2idHash decodes an Argon2id encoded hash string.
// Format: $argon2id$v=19$m=65536,t=3,p=4$<base64_salt>$<base64_hash>
func decodeArgon2idHash(encodedHash string) (*argon2idParams, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, errors.New("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, errors.New("not an argon2id hash")
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != 19 {
		return nil, nil, nil, errors.New("unsupported argon2id version")
	}

	var memory, time uint32
	var parallelism uint8
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}

	return &argon2idParams{
		memory:      memory,
		time:        time,
		parallelism: parallelism,
	}, salt, hash, nil
}
