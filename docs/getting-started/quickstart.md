# Quick Start

This guide walks you through building a simple API with SystemForge authentication.

## Step 1: Create the Application

```go
// main.go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/plexusone/systemforge/identity/ent"
    "github.com/plexusone/systemforge/identity/oauth"
    _ "github.com/lib/pq"
)

func main() {
    // Connect to PostgreSQL
    client, err := ent.Open("postgres",
        "host=localhost port=5432 user=myapp dbname=myapp password=secret sslmode=disable")
    if err != nil {
        log.Fatalf("failed to connect: %v", err)
    }
    defer client.Close()

    // Run migrations
    if err := client.Schema.Create(context.Background()); err != nil {
        log.Fatalf("failed to create schema: %v", err)
    }

    // Create OAuth provider
    cfg := oauth.DefaultConfig(
        "http://localhost:8080",           // Issuer URL
        []byte("your-32-byte-secret-key"), // HMAC secret
    )
    provider, err := oauth.NewProvider(client, cfg)
    if err != nil {
        log.Fatalf("failed to create provider: %v", err)
    }

    // Create OAuth API (endpoints auto-registered)
    oauthAPI, err := oauth.NewAPI(provider, oauth.WithAcceptedClientIDs("my-app"))
    if err != nil {
        log.Fatalf("failed to create oauth api: %v", err)
    }

    // Mount OAuth router (includes all OAuth and discovery endpoints)
    http.Handle("/", oauthAPI.Router())

    // Protected API endpoint
    http.Handle("GET /api/me", oauthAPI.Middleware(http.HandlerFunc(meHandler)))

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func meHandler(w http.ResponseWriter, r *http.Request) {
    userID := oauth.UserIDFromContext(r.Context())
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"user_id":"` + userID + `"}`))
}
```

## Step 2: Create an OAuth App

Before clients can authenticate, you need to create an OAuth app:

```go
// Create a first-party OAuth app (your own frontend)
app, err := client.OAuthApp.Create().
    SetClientID("my-frontend-app").
    SetName("My Frontend App").
    SetAppType("spa").
    SetPublic(true).
    SetFirstParty(true).
    SetRedirectUris([]string{"http://localhost:3000/callback"}).
    SetAllowedScopes([]string{"openid", "profile", "email"}).
    SetAllowedGrants([]string{"authorization_code", "refresh_token"}).
    SetOwnerID(adminUserID).
    Save(context.Background())
```

## Step 3: Test the Flow

### Get Authorization Code

Open in browser:

```
http://localhost:8080/oauth/authorize?
  response_type=code&
  client_id=my-frontend-app&
  redirect_uri=http://localhost:3000/callback&
  scope=openid+profile&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

### Exchange Code for Token

```bash
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code" \
  -d "client_id=my-frontend-app" \
  -d "code=YOUR_AUTH_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

### Access Protected Endpoint

```bash
curl http://localhost:8080/api/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Step 4: Add User Registration

A person is a human principal; the password is a credential that belongs to it.

```go
import (
    "github.com/plexusone/systemforge/identity/credential"
    "github.com/plexusone/systemforge/identity/principal"
)

person, err := principal.NewService(client).CreateHuman(ctx, principal.CreateHumanInput{
    Email:       "user@example.com",
    DisplayName: "John Doe",
})
if err != nil {
    return err
}

err = credential.NewService(client).CreatePassword(ctx, credential.CreatePasswordInput{
    PrincipalID: person.ID,
    Password:    "secure-password",
})
if err != nil {
    return err
}
```

`CreatePassword` hashes the password with Argon2id before storing it.

## Next Steps

- [OAuth Apps](../oauth/apps.md) - Learn about OAuth app configuration
- [Organizations](../identity/organizations.md) - Set up multi-tenancy
- [API Keys](../identity/api-keys.md) - Enable server-to-server access
