# Authorization Code Grant

The Authorization Code grant is the recommended flow for user-facing applications.

## Flow Overview

```
┌──────────┐                              ┌──────────┐
│          │  1. Authorization Request    │          │
│  Client  │ ────────────────────────────▶│  AuthZ   │
│   App    │                              │ Endpoint │
│          │◀─────────────────────────────│          │
└──────────┘  2. Authorization Code       └──────────┘
     │                                          │
     │                                          │
     │        3. Token Request                  │
     │        (code + verifier)                 │
     ▼                                          │
┌──────────┐                              ┌──────────┐
│  Token   │◀─────────────────────────────│   User   │
│ Endpoint │  4. Access + Refresh Token   │  Login   │
└──────────┘                              └──────────┘
```

## PKCE (Proof Key for Code Exchange)

PKCE is required for public clients and recommended for all clients.

### Generate Code Verifier

```javascript
// Client-side (JavaScript)
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
}

function base64URLEncode(buffer) {
    return btoa(String.fromCharCode(...buffer))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
```

### Generate Code Challenge

```javascript
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return base64URLEncode(new Uint8Array(hash));
}
```

## Step 1: Authorization Request

Redirect user to authorization endpoint:

```
GET /oauth/authorize?
  response_type=code&
  client_id=my-app&
  redirect_uri=https://app.example.com/callback&
  scope=openid+profile+email&
  state=xyz123&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `response_type` | Yes | Must be `code` |
| `client_id` | Yes | Your app's client ID |
| `redirect_uri` | Yes | Must match registered URI |
| `scope` | Yes | Space-separated scopes |
| `state` | Recommended | CSRF protection |
| `code_challenge` | Public clients | PKCE challenge |
| `code_challenge_method` | With challenge | Must be `S256` |

## Step 2: User Authentication

SystemForge redirects to your login page if the user isn't authenticated:

```go
// In AuthorizeEndpoint
userID := getUserIDFromSession(r)
if userID == "" {
    http.Redirect(w, r, "/login?redirect="+url.QueryEscape(r.URL.String()), http.StatusFound)
    return
}
```

## Step 3: Authorization Response

After user authorizes, they're redirected back with a code:

```
https://app.example.com/callback?
  code=SplxlOBeZQQYbYS6WxSbIA&
  state=xyz123
```

### Error Response

```
https://app.example.com/callback?
  error=access_denied&
  error_description=The+user+denied+the+request&
  state=xyz123
```

## Step 4: Token Exchange

Exchange the code for tokens. The request carries a DPoP proof for `POST`
at the token endpoint, and the tokens are bound to the proof's key; see
[Calling APIs with DPoP](../guides/dpop-clients.md). If the authorization
request named the key in `dpop_jkt`, only a proof by that key redeems the
code.

```bash
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
DPoP: <proof>

grant_type=authorization_code&
code=SplxlOBeZQQYbYS6WxSbIA&
client_id=my-app&
redirect_uri=https://app.example.com/callback&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

### Confidential Clients

Add client authentication:

```bash
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)
DPoP: <proof>

grant_type=authorization_code&
code=SplxlOBeZQQYbYS6WxSbIA&
redirect_uri=https://app.example.com/callback
```

### Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "DPoP",
  "expires_in": 900,
  "refresh_token": "8xLOxBtZp8",
  "scope": "openid profile email"
}
```

The refresh token is bound to the same key: a refresh needs a proof by it.
A client registered with the legacy `allow_bearer_tokens` exception may
omit the proof and gets `"token_type": "Bearer"`.

## Complete Example (JavaScript)

```javascript
class OAuthClient {
    constructor(config) {
        this.clientId = config.clientId;
        this.redirectUri = config.redirectUri;
        this.authEndpoint = config.authEndpoint;
        this.tokenEndpoint = config.tokenEndpoint;
    }

    async startAuth(scopes) {
        const verifier = this.generateVerifier();
        const challenge = await this.generateChallenge(verifier);
        const state = this.generateState();

        // Store for later
        sessionStorage.setItem('pkce_verifier', verifier);
        sessionStorage.setItem('oauth_state', state);

        const params = new URLSearchParams({
            response_type: 'code',
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            scope: scopes.join(' '),
            state: state,
            code_challenge: challenge,
            code_challenge_method: 'S256'
        });

        window.location.href = `${this.authEndpoint}?${params}`;
    }

    async handleCallback() {
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');
        const state = params.get('state');

        // Verify state
        if (state !== sessionStorage.getItem('oauth_state')) {
            throw new Error('State mismatch');
        }

        const verifier = sessionStorage.getItem('pkce_verifier');

        // Exchange code for tokens
        const response = await fetch(this.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                // A DPoP proof for POST at the token endpoint, signed with
                // a non-extractable WebCrypto key kept for this session.
                'DPoP': await this.dpopProof('POST', this.tokenEndpoint)
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                client_id: this.clientId,
                redirect_uri: this.redirectUri,
                code_verifier: verifier
            })
        });

        return response.json();
    }
}
```

`dpopProof` stands for the application's own proof builder: a JWT with the
public key in its header and `htm`, `htu`, `iat` and a fresh `jti`, signed
with the session's key (see
[Calling APIs with DPoP](../guides/dpop-clients.md#build-a-proof)). A
browser application behind the [BFF](../bff/overview.md) needs none of
this: the BFF holds the key and sends the proofs.

## Server-Side Implementation

```go
// Login handler - after successful authentication
func handleLogin(w http.ResponseWriter, r *http.Request) {
    // Validate credentials
    user, err := validateCredentials(r)
    if err != nil {
        // Show login error
        return
    }

    // Create session
    session := createSession(user.ID)
    setSessionCookie(w, session)

    // Redirect back to OAuth flow
    if redirect := r.URL.Query().Get("redirect"); redirect != "" {
        http.Redirect(w, r, redirect, http.StatusFound)
        return
    }

    // Default redirect
    http.Redirect(w, r, "/", http.StatusFound)
}
```
