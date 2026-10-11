# TRD: SystemForge Authentication & Authorization

> **Status**: Implemented in v0.1.0
>
> **Update (v0.9.0)**: The DPoP implementation was extracted to the standalone
> [`github.com/grokify/goauth/dpop`](https://github.com/grokify/goauth) package
> (API unchanged). SystemForge's `session/bff` layer now consumes it. The DPoP
> file paths below refer to the code's original location; it now lives in
> `goauth/dpop/`. The design described in this document is otherwise unchanged.
>
> This TRD defined the technical design for SystemForge authentication. The implementation follows this design with the following modules:
>
> | Component | Implementation |
> |-----------|----------------|
> | DPoP Keys | `goauth/dpop/keys.go` (was `session/dpop/keys.go`) |
> | DPoP Proof | `goauth/dpop/proof.go` (was `session/dpop/proof.go`) |
> | DPoP Verifier | `goauth/dpop/verifier.go` (was `session/dpop/verifier.go`) |
> | DPoP Middleware | `goauth/dpop/middleware.go` (was `session/dpop/middleware.go`) |
> | BFF Session | `session/bff/session.go` |
> | BFF Store | `session/bff/store.go`, `store_memory.go` |
> | BFF Proxy | `session/bff/proxy.go` |
> | BFF Cookie | `session/bff/cookie.go` |
> | API Keys | `identity/apikey/service.go` |
> | API Key Schema | `identity/ent/schema/api_key.go` |

## Overview

This document defines the technical implementation details for SystemForge's DPoP + BFF authentication architecture.

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                BROWSER                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  React SPA (Dashforge Builder / App1 UI)                          │ │
│  │  - No tokens stored                                                     │ │
│  │  - No crypto keys                                                       │ │
│  │  - Session cookie only                                                  │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │ HTTP-only Cookie
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BFF Layer (Go)                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Session   │  │   Origin    │  │    DPoP     │  │    API Proxy        │ │
│  │  Validator  │─▶│  Validator  │─▶│   Signer    │─▶│    Handler          │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│         │                                                     │              │
│         ▼                                                     │              │
│  ┌─────────────────────────────────────────────────────────┐ │              │
│  │                 Session Store (Redis/Postgres)           │ │              │
│  │  - Access Token (encrypted)                              │ │              │
│  │  - Refresh Token (encrypted)                             │ │              │
│  │  - DPoP Private Key (per-session)                        │ │              │
│  │  - User ID, Org ID, Role                                 │ │              │
│  └─────────────────────────────────────────────────────────┘ │              │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │ DPoP Header + Bearer Token
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SystemForge API Backend                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │    DPoP     │  │  Audience   │  │    Authz    │  │    Business         │ │
│  │  Verifier   │─▶│  Validator  │─▶│  Middleware │─▶│    Logic            │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Module Structure

```
systemforge/
├── session/
│   ├── jwt/                    # Existing JWT service
│   │   ├── service.go
│   │   ├── claims.go
│   │   └── dpop_claims.go      # NEW: DPoP-bound claims
│   │
│   ├── oauth/                  # Existing OAuth handlers
│   │   ├── handler.go
│   │   ├── providers.go
│   │   └── pkce.go             # NEW: PKCE utilities
│   │
│   ├── dpop/                   # NEW: DPoP implementation
│   │   ├── keys.go             # Key generation & management
│   │   ├── proof.go            # Proof creation & validation
│   │   ├── claims.go           # DPoP JWT claims
│   │   └── middleware.go       # DPoP verification middleware
│   │
│   ├── bff/                    # NEW: BFF components
│   │   ├── session.go          # Server-side session management
│   │   ├── store.go            # Session store interface
│   │   ├── store_memory.go     # In-memory store (dev)
│   │   ├── store_redis.go      # Redis store (prod)
│   │   ├── store_postgres.go   # PostgreSQL store (prod)
│   │   ├── cookie.go           # Secure cookie handling
│   │   ├── proxy.go            # API proxy with DPoP injection
│   │   └── middleware.go       # BFF middleware stack
│   │
│   └── middleware/             # Existing + enhanced
│       ├── chi.go
│       ├── http.go
│       ├── context.go
│       ├── origin.go           # NEW: Origin validation
│       └── audience.go         # NEW: Audience validation
│
├── identity/                   # Existing identity schemas
│   └── ent/schema/
│       ├── user.go
│       ├── organization.go
│       ├── membership.go
│       ├── oauth_account.go
│       ├── refresh_token.go
│       └── api_key.go          # NEW: Developer API keys
│
└── authz/                      # Existing authorization
    ├── authorizer.go
    ├── simple/
    └── casbin/
```

## DPoP Implementation

### DPoP Proof Structure (RFC 9449)

```go
// dpop/claims.go
package dpop

import (
    "github.com/golang-jwt/jwt/v5"
)

// ProofClaims represents DPoP proof JWT claims
type ProofClaims struct {
    jwt.RegisteredClaims

    // HTTP method bound to this proof
    HTTPMethod string `json:"htm"`

    // HTTP URI bound to this proof (without query/fragment)
    HTTPURI string `json:"htu"`

    // Access token hash (when used with token)
    AccessTokenHash string `json:"ath,omitempty"`
}

// Header represents DPoP proof JWT header
type Header struct {
    Type      string `json:"typ"` // Always "dpop+jwt"
    Algorithm string `json:"alg"` // ES256, RS256, etc.
    JWK       JWK    `json:"jwk"` // Public key
}

// JWK represents a JSON Web Key
type JWK struct {
    KeyType   string `json:"kty"`
    Curve     string `json:"crv,omitempty"` // For EC keys
    X         string `json:"x,omitempty"`   // For EC keys
    Y         string `json:"y,omitempty"`   // For EC keys
    N         string `json:"n,omitempty"`   // For RSA keys
    E         string `json:"e,omitempty"`   // For RSA keys
}
```

### DPoP Key Generation

```go
// dpop/keys.go
package dpop

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
)

// KeyPair holds a DPoP key pair
type KeyPair struct {
    PrivateKey *ecdsa.PrivateKey
    PublicKey  *ecdsa.PublicKey
    Thumbprint string // JWK thumbprint (for cnf.jkt)
}

// GenerateKeyPair creates a new ES256 key pair for DPoP
func GenerateKeyPair() (*KeyPair, error) {
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }

    thumbprint := computeThumbprint(privateKey.PublicKey)

    return &KeyPair{
        PrivateKey: privateKey,
        PublicKey:  &privateKey.PublicKey,
        Thumbprint: thumbprint,
    }, nil
}

// computeThumbprint computes JWK thumbprint per RFC 7638
func computeThumbprint(pub ecdsa.PublicKey) string {
    // Canonical JWK representation
    canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
        base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
        base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()))

    hash := sha256.Sum256([]byte(canonical))
    return base64.RawURLEncoding.EncodeToString(hash[:])
}
```

### DPoP Proof Creation (BFF Side)

```go
// dpop/proof.go
package dpop

import (
    "crypto/sha256"
    "encoding/base64"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

// ProofParams contains parameters for proof creation
type ProofParams struct {
    Method      string // HTTP method (GET, POST, etc.)
    URL         string // Full URL (scheme + host + path)
    AccessToken string // Optional: bind to specific access token
}

// CreateProof generates a DPoP proof JWT
func CreateProof(keyPair *KeyPair, params ProofParams) (string, error) {
    now := time.Now()

    claims := ProofClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            ID:       uuid.New().String(),
            IssuedAt: jwt.NewNumericDate(now),
        },
        HTTPMethod: params.Method,
        HTTPURI:    params.URL,
    }

    // Bind to access token if provided
    if params.AccessToken != "" {
        hash := sha256.Sum256([]byte(params.AccessToken))
        claims.AccessTokenHash = base64.RawURLEncoding.EncodeToString(hash[:])
    }

    token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

    // Add DPoP-specific header
    token.Header["typ"] = "dpop+jwt"
    token.Header["jwk"] = keyPair.PublicJWK()

    return token.SignedString(keyPair.PrivateKey)
}
```

### DPoP Verification (API Side)

```go
// dpop/middleware.go
package dpop

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "net/http"
    "strings"
    "time"
)

// Verifier validates DPoP proofs
type Verifier struct {
    // Maximum age of proof (prevents replay)
    MaxAge time.Duration

    // Nonce store for replay prevention (optional)
    NonceStore NonceStore
}

// Middleware returns HTTP middleware that validates DPoP proofs
func (v *Verifier) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Check if request uses DPoP
        authHeader := r.Header.Get("Authorization")
        if !strings.HasPrefix(authHeader, "DPoP ") {
            // Not a DPoP request, pass through
            next.ServeHTTP(w, r)
            return
        }

        accessToken := strings.TrimPrefix(authHeader, "DPoP ")
        proofJWT := r.Header.Get("DPoP")

        if proofJWT == "" {
            http.Error(w, "Missing DPoP proof", http.StatusUnauthorized)
            return
        }

        // Verify proof
        claims, err := v.VerifyProof(proofJWT, VerifyParams{
            Method:      r.Method,
            URL:         requestURL(r),
            AccessToken: accessToken,
        })
        if err != nil {
            http.Error(w, "Invalid DPoP proof: "+err.Error(), http.StatusUnauthorized)
            return
        }

        // Add verified info to context
        ctx := context.WithValue(r.Context(), dpopClaimsKey, claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// VerifyParams contains parameters for proof verification
type VerifyParams struct {
    Method      string
    URL         string
    AccessToken string
}

// VerifyProof validates a DPoP proof JWT
func (v *Verifier) VerifyProof(proofJWT string, params VerifyParams) (*ProofClaims, error) {
    // Parse without verification first to get public key from header
    token, parts, err := jwt.NewParser().ParseUnverified(proofJWT, &ProofClaims{})
    if err != nil {
        return nil, fmt.Errorf("parsing proof: %w", err)
    }

    // Verify header
    if token.Header["typ"] != "dpop+jwt" {
        return nil, errors.New("invalid typ header")
    }

    // Extract public key from jwk header
    jwk, ok := token.Header["jwk"].(map[string]interface{})
    if !ok {
        return nil, errors.New("missing jwk header")
    }

    publicKey, err := parseJWK(jwk)
    if err != nil {
        return nil, fmt.Errorf("parsing jwk: %w", err)
    }

    // Verify signature
    token, err = jwt.ParseWithClaims(proofJWT, &ProofClaims{}, func(t *jwt.Token) (interface{}, error) {
        return publicKey, nil
    })
    if err != nil {
        return nil, fmt.Errorf("verifying signature: %w", err)
    }

    claims := token.Claims.(*ProofClaims)

    // Verify method
    if claims.HTTPMethod != params.Method {
        return nil, errors.New("method mismatch")
    }

    // Verify URL
    if claims.HTTPURI != params.URL {
        return nil, errors.New("URL mismatch")
    }

    // Verify age
    if time.Since(claims.IssuedAt.Time) > v.MaxAge {
        return nil, errors.New("proof expired")
    }

    // Verify access token hash
    if params.AccessToken != "" {
        hash := sha256.Sum256([]byte(params.AccessToken))
        expectedATH := base64.RawURLEncoding.EncodeToString(hash[:])
        if claims.AccessTokenHash != expectedATH {
            return nil, errors.New("access token hash mismatch")
        }
    }

    // Check for replay (if nonce store configured)
    if v.NonceStore != nil {
        if v.NonceStore.Exists(claims.ID) {
            return nil, errors.New("proof replay detected")
        }
        v.NonceStore.Add(claims.ID, v.MaxAge)
    }

    return claims, nil
}
```

## BFF Session Management

### Session Store Interface

```go
// bff/store.go
package bff

import (
    "context"
    "time"

    "github.com/google/uuid"
    "github.com/plexusone/systemforge/session/dpop"
)

// Session represents a BFF session
type Session struct {
    ID           string
    UserID       uuid.UUID
    Email        string
    OrgID        *uuid.UUID
    Role         string

    // Tokens (encrypted at rest)
    AccessToken  string
    RefreshToken string
    TokenExpiry  time.Time

    // DPoP key pair for this session
    DPoPKeyPair  *dpop.KeyPair

    // Metadata
    CreatedAt    time.Time
    LastAccessAt time.Time
    UserAgent    string
    IPAddress    string
}

// Store defines the session storage interface
type Store interface {
    // Create creates a new session
    Create(ctx context.Context, session *Session) error

    // Get retrieves a session by ID
    Get(ctx context.Context, id string) (*Session, error)

    // Update updates an existing session
    Update(ctx context.Context, session *Session) error

    // Delete removes a session
    Delete(ctx context.Context, id string) error

    // DeleteByUserID removes all sessions for a user
    DeleteByUserID(ctx context.Context, userID uuid.UUID) error

    // Cleanup removes expired sessions
    Cleanup(ctx context.Context) error
}
```

### BFF Middleware Stack

```go
// bff/middleware.go
package bff

import (
    "net/http"
)

// Config configures the BFF middleware
type Config struct {
    Store           Store
    CookieName      string
    CookieDomain    string
    CookieSecure    bool
    AllowedOrigins  []string
    APIBaseURL      string
    SessionTimeout  time.Duration
}

// Middleware returns the BFF middleware stack
func Middleware(cfg Config) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        // Stack middlewares in order
        handler := next

        // 1. Session validation (extracts session from cookie)
        handler = sessionMiddleware(cfg.Store, cfg.CookieName)(handler)

        // 2. Origin validation (prevents CSRF)
        handler = originMiddleware(cfg.AllowedOrigins)(handler)

        return handler
    }
}

// sessionMiddleware validates session cookie and loads session
func sessionMiddleware(store Store, cookieName string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            cookie, err := r.Cookie(cookieName)
            if err != nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            session, err := store.Get(r.Context(), cookie.Value)
            if err != nil {
                http.Error(w, "Session expired", http.StatusUnauthorized)
                return
            }

            // Add session to context
            ctx := context.WithValue(r.Context(), sessionKey, session)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// originMiddleware validates Origin header
func originMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
    allowed := make(map[string]bool)
    for _, origin := range allowedOrigins {
        allowed[origin] = true
    }

    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            origin := r.Header.Get("Origin")
            if origin == "" {
                // Fall back to Referer for same-origin requests
                origin = r.Header.Get("Referer")
            }

            if origin == "" || !allowed[origin] {
                http.Error(w, "Invalid origin", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

### BFF API Proxy

```go
// bff/proxy.go
package bff

import (
    "io"
    "net/http"
    "net/url"

    "github.com/plexusone/systemforge/session/dpop"
)

// Proxy proxies requests to the API with DPoP injection
type Proxy struct {
    APIBaseURL string
    HTTPClient *http.Client
}

// Handler returns an HTTP handler that proxies to the API
func (p *Proxy) Handler() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        session := SessionFromContext(r.Context())
        if session == nil {
            http.Error(w, "No session", http.StatusUnauthorized)
            return
        }

        // Build target URL
        targetURL, _ := url.Parse(p.APIBaseURL)
        targetURL.Path = r.URL.Path
        targetURL.RawQuery = r.URL.RawQuery

        // Create DPoP proof
        proof, err := dpop.CreateProof(session.DPoPKeyPair, dpop.ProofParams{
            Method:      r.Method,
            URL:         targetURL.String(),
            AccessToken: session.AccessToken,
        })
        if err != nil {
            http.Error(w, "Failed to create proof", http.StatusInternalServerError)
            return
        }

        // Create proxied request
        proxyReq, _ := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)

        // Copy headers (except auth-related)
        for k, v := range r.Header {
            if k != "Cookie" && k != "Authorization" {
                proxyReq.Header[k] = v
            }
        }

        // Add DPoP headers
        proxyReq.Header.Set("Authorization", "DPoP "+session.AccessToken)
        proxyReq.Header.Set("DPoP", proof)

        // Execute request
        resp, err := p.HTTPClient.Do(proxyReq)
        if err != nil {
            http.Error(w, "API error", http.StatusBadGateway)
            return
        }
        defer resp.Body.Close()

        // Copy response
        for k, v := range resp.Header {
            w.Header()[k] = v
        }
        w.WriteHeader(resp.StatusCode)
        io.Copy(w, resp.Body)
    })
}
```

## DPoP-Bound Token Claims

```go
// jwt/dpop_claims.go
package jwt

import (
    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

// DPoPBoundClaims extends standard claims with DPoP binding
type DPoPBoundClaims struct {
    jwt.RegisteredClaims

    // User identity
    UserID         uuid.UUID  `json:"uid"`
    Email          string     `json:"email,omitempty"`

    // Organization context
    OrganizationID *uuid.UUID `json:"oid,omitempty"`
    Role           string     `json:"role,omitempty"`

    // Token type
    Audience       []string   `json:"aud"`
    TokenType      string     `json:"typ"` // "webui" or "api"

    // DPoP confirmation (RFC 9449 Section 6)
    Confirmation   *CNFClaim  `json:"cnf,omitempty"`
}

// CNFClaim represents the confirmation claim for DPoP binding
type CNFClaim struct {
    // JWK Thumbprint of the DPoP public key
    JKT string `json:"jkt"`
}

// IsDPoPBound returns true if this token requires DPoP proof
func (c *DPoPBoundClaims) IsDPoPBound() bool {
    return c.Confirmation != nil && c.Confirmation.JKT != ""
}
```

## Developer API Keys

### API Key Schema

```go
// identity/ent/schema/api_key.go
package schema

import (
    "entgo.io/ent"
    "entgo.io/ent/schema/edge"
    "entgo.io/ent/schema/field"
    "entgo.io/ent/schema/index"
)

// APIKey holds the schema definition for developer API keys.
type APIKey struct {
    ent.Schema
}

func (APIKey) Mixin() []ent.Mixin {
    return []ent.Mixin{
        BaseMixin{TablePrefix: "cf_"},
    }
}

func (APIKey) Fields() []ent.Field {
    return []ent.Field{
        field.String("name").
            NotEmpty().
            Comment("Human-readable name for the API key"),

        field.String("key_prefix").
            MaxLen(8).
            Comment("First 8 chars of key for identification (e.g., 'cf_live_')"),

        field.String("key_hash").
            Sensitive().
            Comment("Argon2id hash of the full API key"),

        field.Strings("scopes").
            Default([]string{}).
            Comment("Allowed scopes for this key"),

        field.Time("expires_at").
            Optional().
            Nillable().
            Comment("Expiration time (nil = never)"),

        field.Time("last_used_at").
            Optional().
            Nillable().
            Comment("Last time this key was used"),

        field.Bool("revoked").
            Default(false).
            Comment("Whether this key has been revoked"),
    }
}

func (APIKey) Edges() []ent.Edge {
    return []ent.Edge{
        edge.From("user", User.Type).
            Ref("api_keys").
            Required().
            Unique(),

        edge.From("organization", Organization.Type).
            Ref("api_keys").
            Unique().
            Comment("Optional org scope (nil = user-level)"),
    }
}

func (APIKey) Indexes() []ent.Index {
    return []ent.Index{
        index.Fields("key_prefix"),
        index.Fields("revoked", "expires_at"),
    }
}
```

## Testing Strategy

### Unit Tests

```go
// dpop/proof_test.go
func TestCreateAndVerifyProof(t *testing.T) {
    keyPair, err := GenerateKeyPair()
    require.NoError(t, err)

    proof, err := CreateProof(keyPair, ProofParams{
        Method:      "POST",
        URL:         "https://api.example.com/resource",
        AccessToken: "test-token",
    })
    require.NoError(t, err)

    verifier := &Verifier{MaxAge: 5 * time.Minute}
    claims, err := verifier.VerifyProof(proof, VerifyParams{
        Method:      "POST",
        URL:         "https://api.example.com/resource",
        AccessToken: "test-token",
    })
    require.NoError(t, err)
    assert.Equal(t, "POST", claims.HTTPMethod)
}

func TestVerifyProof_MethodMismatch(t *testing.T) {
    keyPair, _ := GenerateKeyPair()
    proof, _ := CreateProof(keyPair, ProofParams{
        Method: "POST",
        URL:    "https://api.example.com/resource",
    })

    verifier := &Verifier{MaxAge: 5 * time.Minute}
    _, err := verifier.VerifyProof(proof, VerifyParams{
        Method: "GET", // Wrong method
        URL:    "https://api.example.com/resource",
    })
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "method mismatch")
}
```

### Integration Tests

```go
// bff/proxy_test.go
func TestBFFProxy_DPoPInjection(t *testing.T) {
    // Set up mock API server that validates DPoP
    apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Verify DPoP header present
        assert.True(t, strings.HasPrefix(r.Header.Get("Authorization"), "DPoP "))
        assert.NotEmpty(t, r.Header.Get("DPoP"))

        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"status":"ok"}`))
    }))
    defer apiServer.Close()

    // Set up BFF with session
    store := NewMemoryStore()
    session := &Session{
        ID:          "test-session",
        AccessToken: "test-token",
        DPoPKeyPair: mustGenerateKeyPair(),
    }
    store.Create(context.Background(), session)

    proxy := &Proxy{
        APIBaseURL: apiServer.URL,
        HTTPClient: http.DefaultClient,
    }

    // Create request through BFF
    req := httptest.NewRequest("GET", "/api/test", nil)
    req = req.WithContext(context.WithValue(req.Context(), sessionKey, session))

    w := httptest.NewRecorder()
    proxy.Handler().ServeHTTP(w, req)

    assert.Equal(t, http.StatusOK, w.Code)
}
```

## Security Considerations

### Key Storage

- DPoP private keys stored in encrypted session store
- Keys rotated on token refresh
- Keys deleted on logout

### Replay Prevention

- JTI claim tracked in Redis/memory with TTL
- Proof max age enforced (e.g., 5 minutes)
- Access token hash (ath) prevents proof reuse across tokens

### Cookie Security

```go
// Secure cookie settings
cookie := &http.Cookie{
    Name:     "session",
    Value:    sessionID,
    Path:     "/",
    Domain:   cfg.CookieDomain,
    MaxAge:   int(cfg.SessionTimeout.Seconds()),
    Secure:   true,                // HTTPS only
    HttpOnly: true,                // No JavaScript access
    SameSite: http.SameSiteStrictMode, // CSRF protection
}
```

### Rate Limiting

- Token endpoint: 10 requests/minute per IP
- API endpoints: 1000 requests/minute per session
- Failed auth: 5 attempts then lockout

## Migration Path

### Dashforge Migration

1. Add SystemForge identity schemas (cf_* tables)
2. Migrate users: `users` → `cf_users`
3. Migrate tenants: `tenant` → `cf_organizations` + `cf_memberships`
4. Update auth to use SystemForge JWT + BFF
5. Add DPoP layer
6. Deprecate old tables

### Data Migration SQL

```sql
-- Phase 1: Create SystemForge tables (run by Ent migration)

-- Phase 2: Copy users
INSERT INTO cf_users (id, email, name, password_hash, created_at, updated_at)
SELECT id, email, name, password_hash, created_at, updated_at
FROM users
ON CONFLICT (id) DO NOTHING;

-- Phase 3: Convert tenants to organizations
INSERT INTO cf_organizations (id, name, slug, plan, created_at, updated_at)
SELECT id, name, slug, plan, created_at, updated_at
FROM tenant
ON CONFLICT (id) DO NOTHING;

-- Phase 4: Create memberships (tenant owner = org owner)
INSERT INTO cf_memberships (id, user_id, organization_id, role, created_at, updated_at)
SELECT gen_random_uuid(), u.id, t.id, 'owner', NOW(), NOW()
FROM users u
JOIN tenant t ON u.tenant_id = t.id
ON CONFLICT DO NOTHING;
```

## Performance Targets

| Operation | Target Latency |
|-----------|---------------|
| DPoP proof creation | < 5ms |
| DPoP proof verification | < 10ms |
| Session lookup (Redis) | < 5ms |
| Session lookup (Postgres) | < 20ms |
| Full BFF proxy request | < 50ms overhead |

## References

- [RFC 9449 - OAuth 2.0 DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 7638 - JWK Thumbprint](https://datatracker.ietf.org/doc/rfc7638/)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/rfc7636/)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
