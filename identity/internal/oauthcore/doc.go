// Package oauthcore holds what SystemForge's two Fosite-based
// authorization servers, identity/systemauth and identity/oauth, share to
// issue and accept DPoP-bound tokens (RFC 9449) and to rotate signing keys
// N / N-1:
//
//   - KeyRing: a signing key plus the verification keys tokens are checked
//     against by kid, its JWKS and its Fosite signer;
//   - ParseTokenRequest, VerifyTokenRequestProof, CheckCodeDPoPBinding,
//     BindDPoPGrant, DPoPProofRequiredError and AuthorizationDPoPJKT for the
//     token and authorization endpoints;
//   - AuthenticateAccessToken, AccessTokenCredentials, TokenAuthError and
//     WriteTokenAuthError for resource endpoints;
//   - SetConfirmationClaim for the cnf claim of JWT access tokens.
//
// The package is internal: it is not part of SystemForge's public API.
// It does not depend on either server's session type; callers pass the
// DPoP binding of their own sessions (a key thumbprint, or a function that
// reads it).
package oauthcore
