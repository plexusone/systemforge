package systemauth

import (
	"context"
	"crypto/rsa"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-jose/go-jose/v3"
)

// registerDiscoveryEndpoints registers OIDC discovery endpoints.
func (s *Server) registerDiscoveryEndpoints() {
	// OpenID Connect Discovery
	huma.Register(s.huma, huma.Operation{
		OperationID: "openidConfiguration",
		Method:      http.MethodGet,
		Path:        "/.well-known/openid-configuration",
		Summary:     "OpenID Connect Discovery",
		Description: "Returns the OpenID Provider configuration (RFC 8414).",
		Tags:        []string{"Discovery"},
	}, s.openIDConfigHandler)

	// JSON Web Key Set
	huma.Register(s.huma, huma.Operation{
		OperationID: "jwks",
		Method:      http.MethodGet,
		Path:        "/.well-known/jwks.json",
		Summary:     "JSON Web Key Set",
		Description: "Returns the public keys used to sign tokens (RFC 7517).",
		Tags:        []string{"Discovery"},
	}, s.jwksHandler)
}

// OpenIDConfiguration represents the OpenID Provider configuration.
type OpenIDConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
}

// OpenIDConfigInput is the input for the discovery endpoint (no params).
type OpenIDConfigInput struct{}

// OpenIDConfigOutput wraps the OpenID configuration response.
type OpenIDConfigOutput struct {
	Body OpenIDConfiguration
}

func (s *Server) openIDConfigHandler(_ context.Context, _ *OpenIDConfigInput) (*OpenIDConfigOutput, error) {
	issuer := s.config.Issuer

	config := OpenIDConfiguration{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/oauth/authorize",
		TokenEndpoint:         issuer + "/oauth/token",
		UserinfoEndpoint:      issuer + UserInfoPath,
		JwksURI:               issuer + "/.well-known/jwks.json",
		IntrospectionEndpoint: issuer + "/oauth/introspect",
		RevocationEndpoint:    issuer + "/oauth/revoke",
		ResponseTypesSupported: []string{
			"code",
			"token",
		},
		ResponseModesSupported: []string{
			"query",
			"fragment",
		},
		GrantTypesSupported: []string{
			"authorization_code",
			"client_credentials",
			"refresh_token",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
			"offline_access",
		},
		ClaimsSupported: []string{
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"name",
			"picture",
			"email",
			"email_verified",
		},
		CodeChallengeMethodsSupported: []string{
			"S256",
		},
	}

	return &OpenIDConfigOutput{Body: config}, nil
}

// JWKSInput is the input for the JWKS endpoint (no params).
type JWKSInput struct{}

// JWKSOutput wraps the JWKS response.
type JWKSOutput struct {
	Body jose.JSONWebKeySet
}

func (s *Server) jwksHandler(_ context.Context, _ *JWKSInput) (*JWKSOutput, error) {
	// Create JWK from the RSA public key
	jwk := jose.JSONWebKey{
		Key:       &s.key.PublicKey,
		KeyID:     "systemauth-1", // In production, use a proper key ID
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	return &JWKSOutput{Body: jwks}, nil
}

// PublicKey returns the public RSA key for external verification.
func (s *Server) PublicKey() *rsa.PublicKey {
	return &s.key.PublicKey
}
