package systemauth

import "errors"

// Configuration errors.
var (
	// ErrMissingIssuer is returned when the issuer is not configured.
	ErrMissingIssuer = errors.New("systemauth: issuer is required")

	// ErrKeyGenerationFailed is returned when key generation fails.
	ErrKeyGenerationFailed = errors.New("systemauth: failed to generate signing key")

	// ErrStorageInitFailed is returned when storage initialization fails.
	ErrStorageInitFailed = errors.New("systemauth: failed to initialize storage")
)

// Client errors.
var (
	// ErrClientNotFound is returned when a client is not found.
	ErrClientNotFound = errors.New("systemauth: client not found")

	// ErrClientExists is returned when trying to create a client that already exists.
	ErrClientExists = errors.New("systemauth: client already exists")

	// ErrInvalidClientType is returned when the client type is invalid.
	ErrInvalidClientType = errors.New("systemauth: invalid client type")
)

// Token errors.
var (
	// ErrTokenNotFound is returned when a token is not found.
	ErrTokenNotFound = errors.New("systemauth: token not found")

	// ErrTokenExpired is returned when a token has expired.
	ErrTokenExpired = errors.New("systemauth: token expired")

	// ErrTokenRevoked is returned when a token has been revoked.
	ErrTokenRevoked = errors.New("systemauth: token revoked")

	// ErrInvalidToken is returned when a token is invalid.
	ErrInvalidToken = errors.New("systemauth: invalid token")
)

// Authorization errors.
var (
	// ErrAuthCodeNotFound is returned when an authorization code is not found.
	ErrAuthCodeNotFound = errors.New("systemauth: authorization code not found")

	// ErrAuthCodeExpired is returned when an authorization code has expired.
	ErrAuthCodeExpired = errors.New("systemauth: authorization code expired")

	// ErrAuthCodeUsed is returned when an authorization code has already been used.
	ErrAuthCodeUsed = errors.New("systemauth: authorization code already used")

	// ErrPKCEVerificationFailed is returned when PKCE verification fails.
	ErrPKCEVerificationFailed = errors.New("systemauth: PKCE verification failed")
)

// Federation errors.
var (
	// ErrFederationNotConfigured is returned when federation is not configured.
	ErrFederationNotConfigured = errors.New("systemauth: federation not configured")

	// ErrFederationConnectionFailed is returned when connection to SystemAuth fails.
	ErrFederationConnectionFailed = errors.New("systemauth: failed to connect to SystemAuth")

	// ErrInvalidGlobalToken is returned when a global identity token is invalid.
	ErrInvalidGlobalToken = errors.New("systemauth: invalid global identity token")
)

// User errors.
var (
	// ErrUserNotFound is returned when a user is not found.
	ErrUserNotFound = errors.New("systemauth: user not found")

	// ErrUserExists is returned when trying to create a user that already exists.
	ErrUserExists = errors.New("systemauth: user already exists")
)
