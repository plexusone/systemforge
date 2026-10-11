# SystemForge OAuth 2.0 Server - Technical Requirements Document

> **Status**: Implemented in v0.1.0
>
> This TRD defined the technical design for SystemForge OAuth 2.0 server. The implementation uses Fosite as the OAuth 2.0 library with the following modules:
>
> | Component | Implementation |
> |-----------|----------------|
> | OAuth Provider | `identity/oauth/provider.go` |
> | OAuth Storage | `identity/oauth/storage.go` (Fosite adapter) |
> | OAuth Handlers | `identity/oauth/handlers.go` |
> | OAuth Client | `identity/oauth/client.go` |
> | OAuth Schemas | `identity/ent/schema/oauth_*.go` |
> | Service Account | `identity/ent/schema/service_account.go` |
> | Key Pairs | `identity/ent/schema/service_account_key_pair.go` |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SystemForge OAuth Module                          │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │   oauth/app     │  │ oauth/service   │  │  oauth/token    │         │
│  │                 │  │    account      │  │                 │         │
│  │ • App CRUD      │  │ • SA CRUD       │  │ • Grant flows   │         │
│  │ • Secret mgmt   │  │ • Key pairs     │  │ • Introspection │         │
│  │ • Redirect URIs │  │ • JWT verify    │  │ • Revocation    │         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
│           │                    │                    │                   │
│           └────────────────────┼────────────────────┘                   │
│                                │                                        │
│                    ┌───────────▼───────────┐                           │
│                    │    oauth/handler      │                           │
│                    │                       │                           │
│                    │ • /oauth/authorize    │                           │
│                    │ • /oauth/token        │                           │
│                    │ • /oauth/revoke       │                           │
│                    │ • /oauth/introspect   │                           │
│                    │ • /oauth/userinfo     │                           │
│                    └───────────┬───────────┘                           │
│                                │                                        │
│  ┌─────────────────────────────┼─────────────────────────────┐         │
│  │                 Ent Schemas │                             │         │
│  │  ┌──────────┐  ┌───────────┴──┐  ┌─────────────┐         │         │
│  │  │OAuthApp  │  │ServiceAccount│  │OAuthToken   │         │         │
│  │  └──────────┘  └──────────────┘  └─────────────┘         │         │
│  │  ┌──────────┐  ┌──────────────┐  ┌─────────────┐         │         │
│  │  │AppSecret │  │SAKeyPair     │  │AuthCode     │         │         │
│  │  └──────────┘  └──────────────┘  └─────────────┘         │         │
│  │  ┌──────────┐  ┌──────────────┐  ┌─────────────┐         │         │
│  │  │Consent   │  │TokenFamily   │  │RefreshToken │         │         │
│  │  └──────────┘  └──────────────┘  └─────────────┘         │         │
│  └───────────────────────────────────────────────────────────┘         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Module Structure

```
github.com/plexusone/systemforge/
├── oauth/
│   ├── app/
│   │   ├── service.go          # OAuth app management
│   │   ├── secret.go           # Client secret operations
│   │   └── validation.go       # Redirect URI validation
│   │
│   ├── serviceaccount/
│   │   ├── service.go          # Service account management
│   │   ├── keypair.go          # Key pair generation/storage
│   │   └── jwt.go              # JWT assertion verification
│   │
│   ├── token/
│   │   ├── service.go          # Token issuance/validation
│   │   ├── grants/
│   │   │   ├── authcode.go     # Authorization Code + PKCE
│   │   │   ├── clientcreds.go  # Client Credentials
│   │   │   ├── refresh.go      # Refresh Token
│   │   │   └── jwtbearer.go    # JWT Bearer (RFC 7523)
│   │   ├── introspect.go       # Token introspection
│   │   └── revoke.go           # Token revocation
│   │
│   ├── handler/
│   │   ├── authorize.go        # GET /oauth/authorize
│   │   ├── token.go            # POST /oauth/token
│   │   ├── revoke.go           # POST /oauth/revoke
│   │   ├── introspect.go       # POST /oauth/introspect
│   │   ├── userinfo.go         # GET /oauth/userinfo
│   │   └── discovery.go        # .well-known endpoints
│   │
│   ├── ent/schema/
│   │   ├── oauth_app.go
│   │   ├── app_secret.go
│   │   ├── service_account.go
│   │   ├── sa_key_pair.go
│   │   ├── auth_code.go
│   │   ├── oauth_token.go
│   │   ├── token_family.go
│   │   └── consent.go
│   │
│   ├── middleware/
│   │   ├── bearer.go           # Bearer token validation
│   │   └── scope.go            # Scope checking
│   │
│   └── oidc/
│       ├── claims.go           # ID token claims
│       ├── discovery.go        # OIDC discovery document
│       └── jwks.go             # JWKS endpoint
```

---

## Ent Schemas

### OAuthApp

```go
// oauth/ent/schema/oauth_app.go
package schema

type OAuthApp struct {
    ent.Schema
}

func (OAuthApp) Fields() []ent.Field {
    return []ent.Field{
        field.UUID("id", uuid.UUID{}).Default(uuid.New),

        // Identification
        field.String("client_id").Unique().Immutable().
            DefaultFunc(generateClientID), // cf_app_xxx
        field.String("name").NotEmpty().MaxLen(255),
        field.String("description").Optional().MaxLen(1000),
        field.String("logo_url").Optional(),

        // App type determines allowed grants
        field.Enum("app_type").
            Values("web", "spa", "native", "service").
            Default("web"),

        // Ownership
        field.UUID("owner_id", uuid.UUID{}),           // User who created
        field.UUID("organization_id", uuid.UUID{}).    // Org scope (optional)
            Optional().Nillable(),

        // Configuration
        field.JSON("redirect_uris", []string{}).Default([]string{}),
        field.JSON("allowed_scopes", []string{}).Default([]string{}),
        field.JSON("allowed_grants", []string{}).
            Default([]string{"authorization_code", "refresh_token"}),

        // Token settings
        field.Int("access_token_ttl").Default(900),      // 15 min
        field.Int("refresh_token_ttl").Default(604800),  // 7 days
        field.Bool("refresh_token_rotation").Default(true),

        // Flags
        field.Bool("first_party").Default(false),  // Skip consent
        field.Bool("active").Default(true),
        field.Time("revoked_at").Optional().Nillable(),

        // Timestamps
        field.Time("created_at").Default(time.Now),
        field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
    }
}

func (OAuthApp) Edges() []ent.Edge {
    return []ent.Edge{
        edge.From("owner", User.Type).Ref("oauth_apps").Unique().Required(),
        edge.From("organization", Organization.Type).Ref("oauth_apps").Unique(),
        edge.To("secrets", AppSecret.Type),
        edge.To("tokens", OAuthToken.Type),
        edge.To("consents", Consent.Type),
    }
}

func (OAuthApp) Indexes() []ent.Index {
    return []ent.Index{
        index.Fields("client_id").Unique(),
        index.Fields("owner_id"),
        index.Fields("organization_id"),
    }
}
```

### AppSecret

```go
// oauth/ent/schema/app_secret.go
type AppSecret struct {
    ent.Schema
}

func (AppSecret) Fields() []ent.Field {
    return []ent.Field{
        field.UUID("id", uuid.UUID{}).Default(uuid.New),
        field.UUID("app_id", uuid.UUID{}),

        // Secret is hashed (Argon2id)
        field.String("secret_hash").Sensitive(),
        field.String("secret_prefix").MaxLen(12), // First 8 chars for identification

        // Lifecycle
        field.Time("expires_at").Optional().Nillable(),
        field.Time("last_used_at").Optional().Nillable(),
        field.Bool("revoked").Default(false),

        field.Time("created_at").Default(time.Now),
    }
}

func (AppSecret) Edges() []ent.Edge {
    return []ent.Edge{
        edge.From("app", OAuthApp.Type).Ref("secrets").Unique().Required(),
    }
}
```

### ServiceAccount

```go
// oauth/ent/schema/service_account.go
type ServiceAccount struct {
    ent.Schema
}

func (ServiceAccount) Fields() []ent.Field {
    return []ent.Field{
        field.UUID("id", uuid.UUID{}).Default(uuid.New),

        // Identification (acts like a user)
        field.String("client_id").Unique().Immutable().
            DefaultFunc(generateServiceAccountID), // cf_sa_xxx
        field.String("name").NotEmpty().MaxLen(255),
        field.String("description").Optional().MaxLen(1000),

        // Ownership
        field.UUID("owner_id", uuid.UUID{}),
        field.UUID("organization_id", uuid.UUID{}).Optional().Nillable(),

        // Permissions
        field.JSON("scopes", []string{}).Default([]string{}),
        field.Bool("can_impersonate").Default(false),

        // Status
        field.Bool("active").Default(true),
        field.Time("last_used_at").Optional().Nillable(),

        field.Time("created_at").Default(time.Now),
        field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
    }
}

func (ServiceAccount) Edges() []ent.Edge {
    return []ent.Edge{
        edge.From("owner", User.Type).Ref("service_accounts").Unique().Required(),
        edge.From("organization", Organization.Type).Ref("service_accounts").Unique(),
        edge.To("key_pairs", SAKeyPair.Type),
    }
}
```

### SAKeyPair

```go
// oauth/ent/schema/sa_key_pair.go
type SAKeyPair struct {
    ent.Schema
}

func (SAKeyPair) Fields() []ent.Field {
    return []ent.Field{
        field.UUID("id", uuid.UUID{}).Default(uuid.New),
        field.UUID("service_account_id", uuid.UUID{}),

        // Key identification
        field.String("kid").Unique(), // Key ID for JWKS
        field.Enum("key_type").Values("rsa", "ec"),
        field.Enum("algorithm").Values("RS256", "RS384", "RS512", "ES256", "ES384"),

        // Public key (stored)
        field.Text("public_key_pem"),
        field.JSON("public_key_jwk", map[string]any{}),

        // Private key is NOT stored - given to user once

        // Lifecycle
        field.Time("expires_at").Optional().Nillable(),
        field.Time("last_used_at").Optional().Nillable(),
        field.Bool("revoked").Default(false),

        field.Time("created_at").Default(time.Now),
    }
}
```

### AuthCode

```go
// oauth/ent/schema/auth_code.go
type AuthCode struct {
    ent.Schema
}

func (AuthCode) Fields() []ent.Field {
    return []ent.Field{
        field.UUID("id", uuid.UUID{}).Default(uuid.New),

        // The authorization code (hashed)
        field.String("code_hash").Unique(),

        // Who/what
        field.UUID("user_id", uuid.UUID{}),
        field.UUID("app_id", uuid.UUID{}),

        // PKCE
        field.String("code_challenge").Optional(),
        field.String("code_challenge_method").Optional(), // S256

        // Request parameters (to verify on exchange)
        field.String("redirect_uri"),
        field.JSON("scopes", []string{}),
        field.String("nonce").Optional(), // OIDC

        // Lifecycle
        field.Time("expires_at"),
        field.Bool("used").Default(false),

        field.Time("created_at").Default(time.Now),
    }
}
```

### OAuthToken

```go
// oauth/ent/schema/oauth_token.go
type OAuthToken struct {
    ent.Schema
}

func (OAuthToken) Fields() []ent.Field {
    return []ent.Field{
        field.UUID("id", uuid.UUID{}).Default(uuid.New),

        // What issued this token
        field.UUID("app_id", uuid.UUID{}),
        field.UUID("service_account_id", uuid.UUID{}).Optional().Nillable(),

        // Who this token represents (nil for client_credentials)
        field.UUID("user_id", uuid.UUID{}).Optional().Nillable(),

        // Token family for rotation tracking
        field.UUID("family_id", uuid.UUID{}),

        // Refresh token (hashed)
        field.String("refresh_token_hash").Unique(),

        // What's granted
        field.JSON("scopes", []string{}),

        // Lifecycle
        field.Time("access_expires_at"),
        field.Time("refresh_expires_at"),
        field.Bool("revoked").Default(false),
        field.Time("revoked_at").Optional().Nillable(),
        field.String("revoked_reason").Optional(),

        // Tracking
        field.String("client_ip").Optional(),
        field.String("user_agent").Optional(),
        field.Time("last_used_at").Optional().Nillable(),

        field.Time("created_at").Default(time.Now),
    }
}
```

### TokenFamily

```go
// oauth/ent/schema/token_family.go
// Tracks refresh token chains for rotation and theft detection
type TokenFamily struct {
    ent.Schema
}

func (TokenFamily) Fields() []ent.Field {
    return []ent.Field{
        field.UUID("id", uuid.UUID{}).Default(uuid.New),

        field.UUID("app_id", uuid.UUID{}),
        field.UUID("user_id", uuid.UUID{}).Optional().Nillable(),

        // Current valid token in this family
        field.UUID("current_token_id", uuid.UUID{}).Optional().Nillable(),

        // If a rotated-out token is reused, revoke entire family
        field.Bool("compromised").Default(false),
        field.Time("compromised_at").Optional().Nillable(),

        field.Time("created_at").Default(time.Now),
    }
}
```

### Consent

```go
// oauth/ent/schema/consent.go
type Consent struct {
    ent.Schema
}

func (Consent) Fields() []ent.Field {
    return []ent.Field{
        field.UUID("id", uuid.UUID{}).Default(uuid.New),

        field.UUID("user_id", uuid.UUID{}),
        field.UUID("app_id", uuid.UUID{}),

        // What was consented to
        field.JSON("scopes", []string{}),

        // Lifecycle
        field.Time("granted_at").Default(time.Now),
        field.Time("expires_at").Optional().Nillable(),
        field.Bool("revoked").Default(false),
    }
}

func (Consent) Indexes() []ent.Index {
    return []ent.Index{
        index.Fields("user_id", "app_id").Unique(),
    }
}
```

---

## Token Service

### Access Token Format (JWT)

```go
// oauth/token/claims.go
type AccessTokenClaims struct {
    jwt.RegisteredClaims

    // Standard OAuth claims
    ClientID  string   `json:"client_id"`
    Scope     string   `json:"scope"`      // Space-separated

    // User context (if present)
    UserID    string   `json:"sub,omitempty"`
    Email     string   `json:"email,omitempty"`

    // Organization context
    OrgID     string   `json:"org_id,omitempty"`
    Role      string   `json:"role,omitempty"`

    // Service account
    ServiceAccountID string `json:"sa_id,omitempty"`

    // Token binding (DPoP)
    Cnf       *CnfClaim `json:"cnf,omitempty"`
}

type CnfClaim struct {
    JKT string `json:"jkt"` // JWK thumbprint
}
```

### Grant Handlers

```go
// oauth/token/grants/interface.go
type GrantHandler interface {
    // GrantType returns the grant_type this handler supports
    GrantType() string

    // Validate validates the grant request
    Validate(ctx context.Context, req *TokenRequest) error

    // Execute executes the grant and returns tokens
    Execute(ctx context.Context, req *TokenRequest) (*TokenResponse, error)
}

type TokenRequest struct {
    GrantType    string
    ClientID     string
    ClientSecret string

    // Authorization Code
    Code         string
    RedirectURI  string
    CodeVerifier string

    // Refresh Token
    RefreshToken string

    // JWT Bearer
    Assertion    string

    // Common
    Scope        string
}

type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"` // "Bearer" or "DPoP"
    ExpiresIn    int    `json:"expires_in"`
    RefreshToken string `json:"refresh_token,omitempty"`
    Scope        string `json:"scope,omitempty"`
    IDToken      string `json:"id_token,omitempty"`
}
```

### Authorization Code + PKCE

```go
// oauth/token/grants/authcode.go
type AuthCodeGrant struct {
    store      Store
    tokenSvc   *TokenService
    codeTTL    time.Duration
}

func (g *AuthCodeGrant) GrantType() string {
    return "authorization_code"
}

func (g *AuthCodeGrant) Validate(ctx context.Context, req *TokenRequest) error {
    // 1. Lookup authorization code
    code, err := g.store.GetAuthCode(ctx, hashCode(req.Code))
    if err != nil {
        return ErrInvalidGrant
    }

    // 2. Check expiration
    if time.Now().After(code.ExpiresAt) {
        return ErrInvalidGrant
    }

    // 3. Check if already used
    if code.Used {
        // Possible replay attack - revoke all tokens in family
        g.tokenSvc.RevokeFamily(ctx, code.FamilyID)
        return ErrInvalidGrant
    }

    // 4. Verify PKCE
    if code.CodeChallenge != "" {
        if req.CodeVerifier == "" {
            return ErrInvalidGrant
        }
        challenge := computeS256Challenge(req.CodeVerifier)
        if !secureCompare(challenge, code.CodeChallenge) {
            return ErrInvalidGrant
        }
    }

    // 5. Verify redirect_uri matches
    if req.RedirectURI != code.RedirectURI {
        return ErrInvalidGrant
    }

    // 6. Verify client
    if req.ClientID != code.AppID {
        return ErrInvalidGrant
    }

    return nil
}

func (g *AuthCodeGrant) Execute(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
    // Mark code as used
    code, _ := g.store.GetAuthCode(ctx, hashCode(req.Code))
    g.store.MarkCodeUsed(ctx, code.ID)

    // Generate tokens
    return g.tokenSvc.IssueTokens(ctx, TokenIssueRequest{
        AppID:   code.AppID,
        UserID:  code.UserID,
        Scopes:  code.Scopes,
        Nonce:   code.Nonce,
    })
}
```

### JWT Bearer Grant

```go
// oauth/token/grants/jwtbearer.go
type JWTBearerGrant struct {
    store    Store
    tokenSvc *TokenService
    verifier *JWTVerifier
}

func (g *JWTBearerGrant) GrantType() string {
    return "urn:ietf:params:oauth:grant-type:jwt-bearer"
}

func (g *JWTBearerGrant) Validate(ctx context.Context, req *TokenRequest) error {
    // 1. Parse JWT without verification first
    unverified, err := jwt.ParseUnverified(req.Assertion)
    if err != nil {
        return ErrInvalidGrant
    }

    // 2. Extract issuer (service account ID)
    issuer := unverified.Claims.Issuer

    // 3. Lookup service account
    sa, err := g.store.GetServiceAccount(ctx, issuer)
    if err != nil || !sa.Active {
        return ErrInvalidClient
    }

    // 4. Get the key used to sign (from kid header)
    kid := unverified.Header["kid"].(string)
    keyPair, err := g.store.GetKeyPair(ctx, sa.ID, kid)
    if err != nil || keyPair.Revoked {
        return ErrInvalidGrant
    }

    // 5. Verify signature
    pubKey, err := parsePublicKey(keyPair.PublicKeyPEM)
    if err != nil {
        return ErrInvalidGrant
    }

    claims, err := g.verifier.Verify(req.Assertion, pubKey)
    if err != nil {
        return ErrInvalidGrant
    }

    // 6. Verify claims
    // - iss must equal sub (self-issued)
    // - aud must be token endpoint
    // - exp must be <= 1 hour from now
    // - iat must be in the past
    if err := g.verifyClaims(claims); err != nil {
        return err
    }

    return nil
}

func (g *JWTBearerGrant) Execute(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
    // Parse assertion to get service account
    claims, _ := jwt.Parse(req.Assertion)
    sa, _ := g.store.GetServiceAccount(ctx, claims.Issuer)

    // Issue access token (no refresh token for JWT bearer)
    return g.tokenSvc.IssueTokens(ctx, TokenIssueRequest{
        AppID:            sa.ClientID,
        ServiceAccountID: &sa.ID,
        Scopes:           sa.Scopes,
        NoRefreshToken:   true,
    })
}
```

---

## HTTP Handlers

### Token Endpoint

```go
// oauth/handler/token.go
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        h.errorResponse(w, ErrInvalidRequest, "method not allowed")
        return
    }

    // Parse form
    if err := r.ParseForm(); err != nil {
        h.errorResponse(w, ErrInvalidRequest, "invalid form")
        return
    }

    req := &TokenRequest{
        GrantType:    r.PostFormValue("grant_type"),
        ClientID:     r.PostFormValue("client_id"),
        ClientSecret: r.PostFormValue("client_secret"),
        Code:         r.PostFormValue("code"),
        RedirectURI:  r.PostFormValue("redirect_uri"),
        CodeVerifier: r.PostFormValue("code_verifier"),
        RefreshToken: r.PostFormValue("refresh_token"),
        Assertion:    r.PostFormValue("assertion"),
        Scope:        r.PostFormValue("scope"),
    }

    // Also check Basic auth for client credentials
    if req.ClientID == "" {
        if user, pass, ok := r.BasicAuth(); ok {
            req.ClientID = user
            req.ClientSecret = pass
        }
    }

    // Find grant handler
    handler, ok := h.grants[req.GrantType]
    if !ok {
        h.errorResponse(w, ErrUnsupportedGrantType, "")
        return
    }

    // Authenticate client (except for public clients with PKCE)
    if err := h.authenticateClient(r.Context(), req); err != nil {
        h.errorResponse(w, err, "")
        return
    }

    // Validate grant
    if err := handler.Validate(r.Context(), req); err != nil {
        h.errorResponse(w, err, "")
        return
    }

    // Execute grant
    resp, err := handler.Execute(r.Context(), req)
    if err != nil {
        h.errorResponse(w, err, "")
        return
    }

    // Success response
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Cache-Control", "no-store")
    w.Header().Set("Pragma", "no-cache")
    json.NewEncoder(w).Encode(resp)
}
```

### Authorization Endpoint

```go
// oauth/handler/authorize.go
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
    // Parse request
    req := &AuthorizeRequest{
        ResponseType:        r.URL.Query().Get("response_type"),
        ClientID:            r.URL.Query().Get("client_id"),
        RedirectURI:         r.URL.Query().Get("redirect_uri"),
        Scope:               r.URL.Query().Get("scope"),
        State:               r.URL.Query().Get("state"),
        CodeChallenge:       r.URL.Query().Get("code_challenge"),
        CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
        Nonce:               r.URL.Query().Get("nonce"),
    }

    // Validate client
    app, err := h.store.GetAppByClientID(r.Context(), req.ClientID)
    if err != nil {
        h.renderError(w, "invalid_client", "Unknown client")
        return
    }

    // Validate redirect_uri
    if !h.validateRedirectURI(app, req.RedirectURI) {
        h.renderError(w, "invalid_redirect_uri", "Invalid redirect URI")
        return
    }

    // Validate response_type
    if req.ResponseType != "code" {
        h.redirectError(w, req.RedirectURI, "unsupported_response_type", req.State)
        return
    }

    // Require PKCE for public clients
    if app.AppType == "spa" || app.AppType == "native" {
        if req.CodeChallenge == "" {
            h.redirectError(w, req.RedirectURI, "invalid_request", req.State)
            return
        }
        if req.CodeChallengeMethod != "S256" {
            h.redirectError(w, req.RedirectURI, "invalid_request", req.State)
            return
        }
    }

    // Get authenticated user
    user := auth.UserFromContext(r.Context())
    if user == nil {
        // Redirect to login, then back here
        h.redirectToLogin(w, r)
        return
    }

    // Check consent
    if !app.FirstParty {
        consent, err := h.store.GetConsent(r.Context(), user.ID, app.ID)
        if err != nil || !h.consentCoversScopes(consent, req.Scope) {
            // Show consent screen
            h.renderConsentScreen(w, r, app, req)
            return
        }
    }

    // Generate authorization code
    code, err := h.generateAuthCode(r.Context(), app, user, req)
    if err != nil {
        h.redirectError(w, req.RedirectURI, "server_error", req.State)
        return
    }

    // Redirect with code
    redirectURL := fmt.Sprintf("%s?code=%s&state=%s",
        req.RedirectURI, code, url.QueryEscape(req.State))
    http.Redirect(w, r, redirectURL, http.StatusFound)
}
```

---

## Implementation Tasks

### Phase 1: Foundation (Week 1)

| Task | Description | Files |
|------|-------------|-------|
| 1.1 | Create Ent schemas | `oauth/ent/schema/*.go` |
| 1.2 | Generate Ent code | `go generate ./oauth/ent` |
| 1.3 | OAuth App service | `oauth/app/service.go` |
| 1.4 | App secret management | `oauth/app/secret.go` |
| 1.5 | Token service core | `oauth/token/service.go` |
| 1.6 | JWT signing/verification | `oauth/token/jwt.go` |

### Phase 2: Core Grants (Week 2)

| Task | Description | Files |
|------|-------------|-------|
| 2.1 | Client Credentials grant | `oauth/token/grants/clientcreds.go` |
| 2.2 | Authorization Code + PKCE | `oauth/token/grants/authcode.go` |
| 2.3 | Refresh Token grant | `oauth/token/grants/refresh.go` |
| 2.4 | Token endpoint handler | `oauth/handler/token.go` |
| 2.5 | Authorization endpoint | `oauth/handler/authorize.go` |
| 2.6 | Tests for all grants | `oauth/token/grants/*_test.go` |

### Phase 3: Service Accounts (Week 3)

| Task | Description | Files |
|------|-------------|-------|
| 3.1 | Service account service | `oauth/serviceaccount/service.go` |
| 3.2 | Key pair generation | `oauth/serviceaccount/keypair.go` |
| 3.3 | JWT Bearer grant | `oauth/token/grants/jwtbearer.go` |
| 3.4 | JWT verification | `oauth/serviceaccount/jwt.go` |
| 3.5 | Tests | `oauth/serviceaccount/*_test.go` |

### Phase 4: OpenID Connect (Week 4)

| Task | Description | Files |
|------|-------------|-------|
| 4.1 | ID Token generation | `oauth/oidc/idtoken.go` |
| 4.2 | UserInfo endpoint | `oauth/handler/userinfo.go` |
| 4.3 | Discovery document | `oauth/oidc/discovery.go` |
| 4.4 | JWKS endpoint | `oauth/oidc/jwks.go` |
| 4.5 | Tests | `oauth/oidc/*_test.go` |

### Phase 5: Security & Polish (Week 5)

| Task | Description | Files |
|------|-------------|-------|
| 5.1 | Token introspection | `oauth/handler/introspect.go` |
| 5.2 | Token revocation | `oauth/handler/revoke.go` |
| 5.3 | Refresh token rotation | `oauth/token/rotation.go` |
| 5.4 | Consent management | `oauth/consent/service.go` |
| 5.5 | Rate limiting | `oauth/middleware/ratelimit.go` |
| 5.6 | Audit logging | `oauth/audit/logger.go` |

### Phase 6: App1 Integration (Week 6)

| Task | Description | Files |
|------|-------------|-------|
| 6.1 | Mount OAuth endpoints | `app1/internal/api/oauth.go` |
| 6.2 | Developer portal API | `app1/internal/api/developer.go` |
| 6.3 | Migration scripts | `app1/migrations/*.sql` |
| 6.4 | Integration tests | `app1/internal/api/*_test.go` |
| 6.5 | Documentation | `app1/docs/oauth.md` |

---

## Security Considerations

### Token Security

1. **Access tokens**: Short-lived (15 min), JWT, can be validated without DB lookup
2. **Refresh tokens**: Long-lived, opaque, stored hashed, rotation on use
3. **Authorization codes**: Very short-lived (10 min), single-use, hashed storage

### PKCE Requirements

- Required for `spa` and `native` app types
- Only S256 method supported (plain is insecure)
- Code verifier: 43-128 characters, URL-safe

### Client Authentication

- Confidential clients: client_secret (Argon2id hashed)
- Public clients: PKCE only, no secret
- Service accounts: JWT Bearer with key pairs

### Refresh Token Rotation

```
Refresh #1 → Token A (active)
Refresh #2 → Token A revoked, Token B (active)
Refresh #3 → Token B revoked, Token C (active)

If Token A reused after rotation:
  → Entire family revoked (theft detected)
  → Alert generated
```

### Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/oauth/token` | 100 | 1 min |
| `/oauth/authorize` | 20 | 1 min |
| Failed auth | 5 failures → 15 min lockout |

---

## Testing Strategy

### Unit Tests

- Each grant handler
- Token service
- Secret hashing/verification
- PKCE challenge verification
- JWT signing/verification

### Integration Tests

- Full OAuth flows end-to-end
- Token refresh rotation
- Theft detection
- Consent flows

### Security Tests

- PKCE bypass attempts
- Token replay
- Redirect URI manipulation
- Timing attacks on secret comparison

---

## Open Questions

1. Should we support PAR (Pushed Authorization Requests) in v1?
2. Maximum number of active refresh tokens per user/app?
3. Should expired tokens be hard-deleted or soft-deleted?
4. DPoP support for API tokens (beyond BFF)?
