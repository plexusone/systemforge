# Threat Model

This page describes what SystemForge protects, who it protects it from,
where the trust boundaries are, and which controls in the code address each
threat. It is written for operators deciding how to deploy SystemForge, for
application developers embedding it, and for security reviewers.

Read it together with the [production checklist](production-checklist.md),
which turns the operator-side assumptions below into settings to verify, and
the [security policy](https://github.com/plexusone/systemforge/blob/main/SECURITY.md),
which explains how to report a vulnerability.

## Scope and assumptions

**In scope** is the SystemForge module: SystemAuth (`identity/systemauth`,
`identity/systemauthsvc`, `cmd/systemauth`), the relying-party stack
(`identity/relyingparty`, `identity/appauth`, `session/bff`), OAuth and
token handling (`identity/oauth`, `identity/token`, `identity/dpopproof`),
organizations, invitations, SCIM and managed principals, the authorization
layer (`authz`, `authzguardsql`), connections and their credential vault
(`connections`, `keys`), billing (`billing`), and the database helpers
(`rls`, `multiapp`).

**Out of scope** are the applications built on SystemForge (their own
handlers, data model and business logic), the upstream libraries
SystemForge depends on (reported to their maintainers), and the
infrastructure an operator runs it on.

The model assumes that:

- **TLS terminates at a CDN or edge proxy**, the issuer and every
  application are served over https, and the hop from the edge to the
  origin is TLS that the edge verifies.
- **The origin accepts traffic only from the edge.** Clients cannot reach
  the application or SystemAuth directly and bypass the edge's limits.
- **Secrets come from a secret store**: the signing key, the token HMAC
  secret, BFF sealing keys, DPoP key pairs, the vault root key, database
  passwords and payment-provider keys are not committed, not passed on
  command lines and not logged.
- **The operator walks the production checklist**: no dev mode, shared
  stores when more than one instance runs, separate database logins for the
  application and for migrations, and row-level security enabled.
- **The host and its operating system are trusted.** Someone with root on
  the host, or with access to its memory, can read every key it holds. This
  model does not try to defend against that.
- **Dependencies are kept current.** `govulncheck` runs in CI, and the Go
  toolchain version carries the standard library's security fixes.

## Assets

| Asset | Why it matters | Where it lives |
|-------|----------------|----------------|
| **Token signing keys** | Sign every ID token and access token. Whoever holds one can mint a token for any principal, client and audience. | SystemAuth's key ring (`identity/systemauth`), loaded from the secret store |
| **Token HMAC secret** | Protects the opaque refresh tokens and authorization codes. Without it, a code or refresh token cannot be verified across a restart or another instance. | `tokens.hmac_secret` in SystemAuth's configuration |
| **DPoP key pairs** | Bind access tokens to a key the client holds (RFC 9449). A relying party's key, together with a session's refresh token, lets its holder act as that session. | Relying-party configuration and BFF sessions (`session/bff`, `identity/relyingparty`) |
| **BFF session sealing keys** | Encrypt the tokens and DPoP private keys kept in server-side sessions. | The BFF key ring (`session/bff`) |
| **Connection-credential vault and its root key** | The vault holds the credentials an organization connects to third-party services; the root key decrypts it. | `connections`, `keys` |
| **Refresh tokens and sessions** | Long-lived access: login sessions at SystemAuth, refresh token families, and BFF sessions at each application. | SystemAuth storage, BFF session stores |
| **Principal and organization data** | People, service accounts, managed principals and agents; organizations, memberships, roles and invitations. | Postgres, through Ent (`identity/*`) |
| **The authorization graph** | Relationships that grant access when the authorizer runs in ReBAC mode. A stale relationship is a grant nobody intended. | SpiceDB (`authz/spicedb`) |
| **Billing state and payment-provider credentials** | Subscriptions, licenses and seats decide what an organization may use; the provider's secret key and webhook signing secrets let their holder create charges or forge events. | `billing`, `marketplace`, Postgres, the secret store |
| **Audit records** | The evidence an incident review needs: who changed whose access, and when. | `contract/audit`, the audit emitter given to SystemAuth |

## Actors

| Actor | Capabilities | Trusted for |
|-------|--------------|-------------|
| **Anonymous internet user** | Sends any request to any public endpoint, at any rate the edge allows. | Nothing |
| **Signed-in user** | Holds a SystemAuth login session and, at each application, a BFF session or DPoP-bound tokens. | Their own account and the access their memberships grant |
| **Organization admin** | Manages one organization's members, invitations, roles, SCIM tokens and connections. | Their organization only, never another tenant |
| **Managed principal** | An account an organization creates and controls; it signs in only to clients that allow managed principals. | Its organization's resources, as its roles allow |
| **Service account** | Automation that holds a private key and obtains DPoP-bound tokens through the JWT-bearer grant. | Its one organization, as its roles allow |
| **Relying-party application** | An OAuth client that federates to SystemAuth and verifies its tokens. | Its own client and its own audience, not other applications' |
| **SCIM provider** | An organization's identity provider, holding a tenant SCIM token. | Users it provisioned and memberships in its organization |
| **Agent or AAuth issuer** | An agent signs requests; a Person Server or agent provider issues auth tokens for it. | What the person it acts for delegated, at a resource that trusts the issuer |
| **Payment provider** | Sends signed webhooks and answers API calls. | Payment facts it signs; never redirect targets or authorization decisions |
| **Operator** | Deploys, configures and holds the secrets. | Everything; the operator is the trust root |
| **Malicious code in the same process** | A compromised dependency, or an embedded application with a vulnerability, in a host that also runs SystemAuth. | Nothing, but it shares memory with the keys (see [Residual risks](#residual-risks-and-accepted-trade-offs)) |

## Trust boundaries

```text
            internet
               │
     ┌─────────▼─────────┐
     │ CDN / edge proxy  │  TLS, WAF, edge rate limits
     └─────────┬─────────┘
               │ verified TLS, origin locked to the edge
     ┌─────────▼─────────┐
     │ reverse proxy on  │  sets the client-address header
     │ the host          │
     └──┬─────────────┬──┘
        │             │
 ┌──────▼──────┐ ┌────▼──────────────┐       ┌───────────────────┐
 │ SystemAuth  │ │ application       │◄─────►│ relying-party     │
 │ (embedded   │ │ (BFF, appauth,    │ OIDC, │ apps elsewhere    │
 │  or alone)  │ │  app code)        │ JWKS  └───────────────────┘
 └──┬───┬───┬──┘ └──┬──────┬─────┬──┘
    │   │   │       │      │     │
    │   │   └──► social identity providers, AAuth issuers
    │   │           │      │     │
 ┌──▼───▼───────────▼┐ ┌───▼──┐ ┌▼────────┐     ┌──────────────────┐
 │ Postgres with RLS │ │Redis │ │ SpiceDB │     │ payment provider │
 └───────────────────┘ └──────┘ └─────────┘     │  and webhooks    │
                                                └──────────────────┘
```

1. **CDN or edge proxy.** The only path from the internet. Everything that
   reaches the origin passed it, and the client-address header it sets is
   believed only from its address ranges.
2. **Reverse proxy on the host.** Routes by host name to SystemAuth and the
   applications, and passes on, or sets, the client-address header.
3. **SystemAuth embedded in the application process.** When a host binary
   embeds SystemAuth (`identity/systemauthsvc`), the signing key and the
   applications' code share one address space. The boundary between them is
   the Go API, not a process boundary.
4. **Relying-party applications.** Other processes, possibly other teams,
   that trust SystemAuth's tokens. Each must accept only tokens addressed to
   it.
5. **Postgres with row-level security.** The application's database login is
   confined to the tenant set on each transaction.
6. **SpiceDB.** Holds the authorization graph; the application writes it and
   asks it for decisions.
7. **Redis.** Shared DPoP replay cache, rate-limit counters and BFF sessions.
8. **The payment provider and its webhooks.** Inbound webhooks are untrusted
   until verified; outbound calls carry the provider secret.
9. **Upstream social identity providers.** Assert identities and email
   addresses that SystemAuth links to accounts.

## Threats and mitigations

The tables use STRIDE: **S**poofing, **T**ampering, **R**epudiation,
**I**nformation disclosure, **D**enial of service and **E**levation of
privilege. "Where" names the package that holds the control.

### Edge proxy and host reverse proxy

| STRIDE | Threat | Mitigation | Where |
|--------|--------|------------|-------|
| S | A client sets a forwarding header to pose as another address and escape per-address limits or lockouts | Client addresses come from the configured header only when the request arrives from a trusted proxy network | `session/bff` (`ClientIPConfig`), `session/ratelimit` |
| T | A rewritten path makes the DPoP proof's URL differ from the one the server checks, or lets a proof for one URL pass at another | Proofs are checked against the configured external base URL | `identity/relyingparty` (`DPoPConfig.BaseURL`), `session/middleware` |
| I | Codes, keys and invitation tokens in URLs reach tracing and metrics | Spans and metrics carry the matched route pattern, not the raw URL | `observability`, `productgraph` |
| D | Credential stuffing and token-endpoint floods | Edge rate-limit rules on the token, login and sign-up paths; in-app limits with shared counters; password lockout per identifier | Edge configuration, `session/ratelimit`, `session/bff`, `identity/security` |
| E | Plain-HTTP hop exposes cookies and tokens | `__Host-` cookies are Secure; HSTS on https issuers; production refuses an http issuer | `identity/systemauth`, `identity/systemauthsvc` |

### SystemAuth (the authorization server)

| STRIDE | Threat | Mitigation | Where |
|--------|--------|------------|-------|
| S | A stale verified email at a social provider signs in to the address's current owner | An identity links by email only when the provider is authoritative for the address; GitHub uses the primary email only | `identity/systemauth` (social directory), `identity/oauthclient` |
| S | Someone pre-registers another person's address | Sign-up requires proof of the address; a changed email becomes unverified | `identity/signup`, `identity/principal` |
| S | Another site signs a visitor into an account it controls (login CSRF) | The login-token exchange requires an allowed Origin or Referer | `identity/systemauth` (login-token exchange) |
| S | Guessing passwords, or learning which accounts exist from response time | Lockout per identifier whether or not the account exists; unknown accounts spend one Argon2id verification | `identity/security`, `identity/systemauth` |
| T | An authorization code exchanged twice, or a refresh token rotated twice, by concurrent requests | Invalidation matches only an unused code; rotation retires a token only while it is active; reuse revokes the family | `identity/systemauth` (storage), `identity/oauth` |
| T | A token bound to a key nobody proved to hold | Tokens bind only to a verified DPoP proof | `identity/token`, `identity/dpopproof` |
| T | A replayed DPoP proof against another instance | A replay cache shared by every instance; production refuses a per-instance cache unless one instance is declared | `identity/dpopproof`, `identity/systemauthsvc` |
| I | Clickjacking and content sniffing on sign-in and consent pages | Content security policy with `frame-ancestors 'none'`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, HSTS | `identity/systemauth` (security headers) |
| I | Open redirect after sign-in or logout | Redirect targets are checked against configured allowlists and registered redirect URIs | `identity/systemauth` (social redirect), `identity/oauth` |
| I | An access-change feed or back-channel delivery reveals other organizations' changes | The feed and deliveries are scoped to each client's organizations | `identity/systemauth` (access changes, back-channel) |
| D | Oversized token requests | A 1 MB body limit before the form is parsed | `identity/systemauth`, `identity/oauth` |
| E | Startup in production with insecure defaults: no HMAC secret, bearer-only clients, shared-secret client credentials, per-instance replay cache | Fail-closed production checks, each with a named waiver logged at startup | `identity/systemauth` (production), `identity/systemauthsvc` |
| E | A managed principal's session authorizes a client that does not allow managed principals | The authorize and token endpoints refuse it | `identity/systemauth`, `identity/managedprincipal` |
| E | Tokens of a deleted or deactivated principal keep working | Unknown or inactive subjects are inactive and their token family is revoked; access changes refuse older tokens | `identity/systemauth`, `identity/accesschange`, `identity/relyingparty` (`RevocationCache`) |

### Relying-party applications, the BFF and `appauth`

| STRIDE | Threat | Mitigation | Where |
|--------|--------|------------|-------|
| S | A token issued to another client, or an ID token, used as this application's access token | `VerifyAccessToken` requires an accepted `client_id`, the configured audience and an access-token `typ` | `identity/relyingparty`, `session/jwt`, `multiapp` |
| S | A stolen access token replayed as a bearer token | Tokens are DPoP-bound; a bound token presented as `Bearer` is always refused; proofs are single-use | `identity/relyingparty`, `session/middleware`, `goauth/dpop` |
| S | A forged JWT makes the client sign a DPoP proof for it | The `cnf` binding is read only after the signature and issuer verify | `identity/relyingparty` (`Client.Transport`) |
| S | A long-lived static API key, whose access does not follow membership changes, used as a second way in | `appauth` and `relyingparty` accept no static API keys; command-line tools use `identity/publicclient` and automation uses service accounts | `identity/appauth`, `identity/relyingparty`, `identity/publicclient`, `identity/serviceaccount` |
| T | A cross-site request rides the session cookie (CSRF) | State-changing requests, and proxied requests of any method, must come from an allowed origin; the cookie is `__Host-`, host-only and SameSite | `session/bff` (origin), `identity/relyingparty` |
| T | A sibling subdomain sets or overwrites the session cookie | `__Host-sf_session`, always host-only | `session/bff` |
| T | Proxy path traversal (`/api/../../other`) reaches an upstream outside its base path with the user's token | Dot segments and encoded slashes are refused | `session/bff` (proxy) |
| T | Client-supplied identity headers (`X-User-Id`) reach upstreams | Only the configured headers are forwarded; identity, routing and forwarding headers are stripped | `session/bff` (proxy) |
| I | Tokens and DPoP private keys read from a session store | Sessions are sealed with key IDs, bound to the session and column; Redis off loopback requires TLS and a password | `session/bff` (sealer, stores) |
| R | Logout reports success while the session stays valid | Logout fails closed when the store fails, and deletes only a session the store returned | `session/bff` |
| E | A session that never ends | Idle timeout and maximum lifetime | `session/bff` |
| E | A route registered with no actions allows every caller | `CanAll` with no actions denies; the middleware constructors panic without actions | `authz` |
| E | A resource named in the request checked against the caller's role in another organization | The resource's organization comes only from the extractor | `authz` |
| E | A principal authorized for no entity gets an unrestricted query policy | `PolicyBuilder.Build` returns `ErrNoAuthorizedEntities`; every entity and field has a concrete resource | `authzguardsql` |

### Organizations, invitations, SCIM and delegation

| STRIDE | Threat | Mitigation | Where |
|--------|--------|------------|-------|
| S | A SCIM credential reads or changes another tenant's users | Each request is bound to the credential's organization; requests without a scope are refused | `identity/scim` |
| S | SCIM rewrites the login email of a user who also belongs elsewhere (account takeover) | A tenant changes email, name and photo only for users it provisioned that belong to no other organization | `identity/scim` |
| T | An unsupported SCIM filter matches every user | Such filters fail with `invalidFilter` | `identity/scim` |
| T | Invite accept racing a revoke still creates the membership | Every invite transition is conditional on the invite being pending; acceptance requires the inviter's current authority | `identity/invite` |
| I | Invitations listed for an unverified email claim | Listing and answering require a verified email | `identity/invite` |
| I | SCIM or API responses carry database error text or password hashes | Unexpected errors are logged and answered generically; passwords are hashed and never returned | `identity/scim` |
| E | An admin adds another tenant's managed principal without consent | Direct adds need `APIConfig.DirectAdd` or platform administration; refusals are indistinguishable | `identity/organization` |
| E | SCIM suspends or deletes an organization's owner, or restores a former admin's role | Owners are refused with 403; a restored membership gets the default role | `identity/scim`, `identity/organization` |
| E | Any principal with `can_delegate` takes over another organization's agent | `ErrAlreadyDelegated` and `ErrCrossOrganization` | `identity/delegation` |

### Agents and AAuth issuers

| STRIDE | Threat | Mitigation | Where |
|--------|--------|------------|-------|
| S | An agent provider claims another domain's agents | An agent token is accepted only when the agent's domain is its issuer's host; issuers are limited to `TrustedIssuers` and the allowed issuer kind | `identity/requestprincipal/aauthrs` |
| T | A request signed for another resource replayed here | The signature's authority defaults to this resource's host | `identity/requestprincipal/aauthrs` |
| E | Issuer metadata fetches reach internal addresses | The resource fetches through an egress-restricted HTTP client the application supplies | `identity/requestprincipal/aauthrs` |

### Postgres with RLS

| STRIDE | Threat | Mitigation | Where |
|--------|--------|------------|-------|
| T | SQL injection through table, column, policy, role or schema names | Identifiers are validated and quoted | `rls`, `multiapp` |
| I | A pooled connection keeps another application's `search_path` | `SET LOCAL` inside a transaction | `multiapp` |
| E | The application login bypasses RLS or changes the schema | Separate logins for the application and for migrations; the tenant is set per transaction | `rls`, operator configuration |
| T | Concurrent seat assignments overrun a seat limit | A conditional increment inside a transaction | `marketplace` |

### SpiceDB (the authorization graph)

| STRIDE | Threat | Mitigation | Where |
|--------|--------|------------|-------|
| E | A deactivated member, deleted user or demoted collaborator keeps access in the graph | Deactivation, demotion and deletion remove relationships before committing | `identity/organization`, `identity/principal`, `identity/scim` |
| E | A failed graph write after a committed revocation leaves access granted; a late grant undoes a revocation | Revocations remove graph access first; grants re-read the rows under graph locks | `identity/organization`, `identity/approle`, `identity/graphlock`, `authz/mode` |
| E | A connection's creator keeps rights after leaving the organization | Creator rights require current membership of the owning organization | `connections` |
| S | A local process writes relationships to the embedded SpiceDB server | An in-memory listener and a random 32-byte key | `authz/spicedb` |

### Redis

| STRIDE | Threat | Mitigation | Where |
|--------|--------|------------|-------|
| I | Session IDs and sealed sessions cross the network in clear text | A non-loopback server requires TLS with certificate verification and a password | `session/bff` (omnistorage store) |
| T | One application's session index shared with another's | A site ID is required and scopes the key prefix | `session/bff` |
| D | A parallel burst counted as one request | Each sliding-window entry has a unique random member | `session/ratelimit` |

### Payment provider and webhooks

| STRIDE | Threat | Mitigation | Where |
|--------|--------|------------|-------|
| S | A forged webhook grants a license or plan | Signatures are verified with a configured secret, fail closed without one, and bodies are size-limited | `billing` (webhook handler) |
| T | A replayed or reordered event applies twice or rolls state back | Processed event IDs under a unique constraint; a per-account lock across instances; state re-read from the provider | `billing`, `billing/pglock` |
| T | A failed authorization-graph sync leaves a paid entitlement unapplied | Every apply writes the graph again, so the provider's redelivery repairs it | `billing` (sink) |
| I | Checkout or portal redirects to a request-supplied URL (open redirect) | Redirect URLs are configured on the server; hosts are allowlisted | `billing` (checkout) |
| I | Error detail in webhook or checkout responses | Fixed messages in responses; causes are logged | `billing` |
| E | A member starts a checkout or opens the portal for another organization | The organization comes from the caller's session, an organization-manage check runs, and the customer is found server-side | `billing` (checkout) |

### Connections and the credential vault

| STRIDE | Threat | Mitigation | Where |
|--------|--------|------------|-------|
| I | One backup holds both the key ring and the root key that decrypts it | Root keys in or under the keys directory are refused | `keys` |
| I | Provider requests reach internal or cloud metadata addresses (SSRF) | An egress policy allows only public addresses over https; the development allowlist never admits link-local or metadata addresses | `identity/systemauthsvc` (connections), `connections` |
| D | Oversized plaintext sealed into the store | The sealer and the row key ring refuse plaintext over 64 MiB | `session/bff`, `identity/relyingparty/pgstore` |

### Upstream social identity providers

| STRIDE | Threat | Mitigation | Where |
|--------|--------|------------|-------|
| S | A provider asserts an email it is not authoritative for | Linking by email only for authoritative providers and domains | `identity/systemauth` (social directory) |
| T | The OAuth client state cookie is set without Secure or with a weak SameSite | `__Host-sf_oauth_client_state`, Secure, HttpOnly, SameSite=Lax | `identity/oauthclient` |
| T | A crafted state or redirect parameter sends the user elsewhere | State is bound to the browser and redirects are allowlisted | `identity/oauthclient`, `identity/systemauth` (social redirect) |

### Audit and repudiation across boundaries

| STRIDE | Threat | Mitigation | Where |
|--------|--------|------------|-------|
| R | Changes to managed principals and SCIM tokens cannot be traced | An audit emitter records managed-principal actions and SCIM token issue, rotation, revocation and failed authentication | `identity/systemauthsvc`, `contract/audit` |
| T | A token for one hosted application's audit stream repoints another's | The audit stream state belongs to each `contract.API` | `contract` |
| R | Access changes are not visible to applications | Every change to a principal's access is recorded and fed to clients, which refuse older tokens | `identity/accesschange`, `identity/relyingparty` |

## Residual risks and accepted trade-offs

- **The signing key shares the process with application code when
  SystemAuth is embedded.** A vulnerability in any embedded application, a
  debug endpoint or a heap dump can expose the key that signs every token.
  This is accepted for hosts that run a small set of first-party
  applications from one codebase; prefer the standalone binary when
  third-party code runs in the host. See
  [Embedding SystemAuth](../systemauth/embedding.md#security-trade-off).
- **Per-instance stores are safe only on one instance.** In-memory replay
  caches, rate-limit counters and session stores are accepted when exactly
  one instance runs. Production refuses a per-instance DPoP replay cache
  unless `dpop.single_instance` declares it; rate-limit counters and other
  stores rely on the operator following the
  [production checklist](production-checklist.md#shared-stores).
- **Rate limiting depends on the edge and on the client-address rule.**
  In-app limits exist for password attempts, BFF endpoints, managed-principal
  code routes and SCIM bulk operations, but the default per-address and
  per-route policies, and the single client-address rule shared by
  SystemAuth, the BFF and `appauth`, are being completed in the current
  hardening phase. Until an application runs a release with them, the edge
  rate-limit rule on the token, login and sign-up paths is the primary
  control, and per-address limits are only as good as the trusted-proxy
  configuration.
- **No external penetration test has been done yet.** The controls above
  come from internal review and the security fixes recorded in the
  changelog. An independent test is planned before wide production use.
- **Unbound bearer tokens remain possible by waiver.** Clients registered
  with `allow_bearer_tokens`, and applications that set `AllowBearerTokens`,
  accept tokens that work for whoever holds a copy. Production refuses them
  unless waived, and each waiver is logged at startup.
- **The `identity/apikey` package and the `session/middleware` API key
  middleware remain** for services outside the relying-party stack that
  manage keys of their own. Keys checked there carry the scopes recorded
  when they were created, and their owner's status is checked on every
  request, but they do not follow membership changes the way access tokens
  do.
- **Upstream providers are trusted for what they assert.** A compromised
  social identity provider, AAuth issuer or payment provider can assert
  false identities or payment facts within the limits above.

## Keeping the model current

- **Every security fix updates the model.** A fix recorded under
  `security` in the changelog also adds or changes a row here, in the same
  release.
- **New trust boundaries are added before they ship.** A new external
  service, store, protocol or credential type gets its boundary and threats
  written down in the change that introduces it.
- **Each minor release reviews the residual risks**, removing those that
  were closed and adding accepted trade-offs that were introduced.
- **The production checklist follows the assumptions.** An assumption that
  the operator must uphold appears as an item in the
  [production checklist](production-checklist.md).
