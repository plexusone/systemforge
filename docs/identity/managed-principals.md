# Managed Principals

A **managed principal** is a human with at least one active **manager**: an
account created and controlled by people who have a verified email. The
managed principal may have an email of its own or none. SystemForge provides the
primitive; applications supply the meaning. A learning application maps a
child to a managed principal and a teacher or parent to a manager, but the
same shape fits a caregiver and a dependent, a coach and an athlete, or an
organization provisioning an account a person claims later.

Email stays required by default. Managed principals exist only where a
deployment and an OAuth client both opt in, and the design of record is
[ADR-005](../design/adrs/ADR-005-managed-principals-and-manager-relationships.md).

## The Primitive

A managed principal is an ordinary `Principal(type=human)` with a `Human`
row and an active manager relationship. Management comes from the
relationship, not from the email
([ADR-009](../design/adrs/ADR-009-management-is-a-relationship.md)):

| Field | Value |
|-------|-------|
| `identifier` | `human:<principal-id>` without an email, a lookup key and never an address; the email when there is one |
| `capabilities` | `can_access_ui` only: no profile management, no delegation |
| `sf_humans.email` | Optional; unverified when given at creation |

SystemForge enforces these invariants, transactionally:

1. A managed principal has **at least one active manager** unless it has a
   **verified email**. Removing the last manager of a principal without
   one is refused with `ErrLastManager`; deactivate or delete the
   principal instead.
2. A manager is an **active human with an email** who is not itself
   managed.
3. Managed principals are created only when the **deployment and the
   requesting client** both allow them.
4. A managed principal may have an email, from creation
   (`CreateInput.Email`, unverified until `VerifyEmail`) or attached later
   (`AttachVerifiedEmail`). It stays managed; the verified email is what
   allows its last manager to be removed.
5. A principal with no manager cannot be given one by a manager
   (`AddManager` and claims return `ErrNotManaged`): entering management
   takes the principal's own consent.

## Enabling

Both switches default to off. In the SystemAuth configuration:

```yaml
managed_principals:
  enabled: true
  login_token_ttl: 720h        # default lifetime of reusable login tokens
  login_token_max_ttl: 9600h   # ceiling on any login token
  single_use_token_ttl: 20m    # default lifetime of single-use tokens

clients:
  - id: learning-app
    managed_principals: true
    login_token_ttl: 7200h     # optional: this client's own default
```

Dynamically registered clients carry the same settings on `OAuthApp`
(`managed_principals_enabled`, `login_token_ttl`). The single check every
path uses is `(*systemauth.Server).ManagedPrincipalsAllowed(ctx, clientID)`.

The browser login session is shared by every client, so the check is made
for each client, not only the one a login token was exchanged for:
`/oauth/authorize` answers `access_denied`, and the token endpoint
`invalid_grant`, when a managed principal (one with an active manager,
whether or not it has an email) is signed in and the client does not allow
managed principals.

## Roles

Two manager roles are built in:

| Role | Authority |
|------|-----------|
| `guardian` | Full control: consent, deletion, billing, credentials, and adding or removing other managers |
| `educator` | Operational control: credentials, profile reads, and issuing a claim so a guardian can join. No deletion, billing, or consent |

They are relations on `principal` in the base authorization schema, with
these platform permissions:

| Permission | Granted to |
|------------|-----------|
| `manage_account` | `guardian` |
| `manage_credentials` | `guardian`, `educator` |
| `view_profile` | `guardian`, `educator` |
| `manage_managers` | `guardian` |

An `educator` cannot delete a managed principal, even one that never
received a guardian; that is a guardian or platform-administrator action.

Applications may register further roles with `managedprincipal.WithRoles`.
They grant no platform permissions; give them meaning in the application's
authorization facets (see [Authorization](#authorization)).

## Creating a Managed Principal

```go
svc := managedprincipal.NewService(entClient, systemAuthServer,
    managedprincipal.WithAuditEmitter(auditEmitter),
    managedprincipal.WithAuthzSyncer(syncer, authz.SyncModeStrict),
)

learnerID, err := svc.Create(ctx, managedprincipal.CreateInput{
    ClientID:    "learning-app",
    DisplayName: "Robin",
    Managers: []managedprincipal.ManagerInput{
        {PrincipalID: teacherID, Role: managedprincipal.RoleEducator},
    },
    ActorID: teacherID,
})
```

The principal, its human row, and its manager relationships are written in
one transaction. Nobody becomes a manager without agreeing: `Create` names
only the acting manager, and other managers join by accepting an
invitation or redeeming a claim. `RemoveManager` deactivates a
relationship. Every action is audited through `contract/audit`.

Trusted administrator tooling, such as a migration, can build the service
with `managedprincipal.WithDirectManagerAdds()`. `Create` may then name
other managers, and `AddManager` attaches one directly; it is idempotent
and reactivates a removed relationship. Without the option both return
`ErrConsentRequired`.

## Sign-in with Login Tokens

A **login token** is a manager-issued sign-in secret for a managed principal.
Applications render it as a QR code, a printed card, or a link; SystemForge
does not care which.

```go
tok, err := svc.IssueLoginToken(ctx, managedprincipal.IssueLoginTokenInput{
    ManagedID: learnerID,
    ClientID:  "learning-app",
    IssuedBy:  teacherID,
    Name:      "Robin's card",
})
// tok.PlainToken is shown once; only its hash is stored.
```

Tokens are `SFLT` followed by 52 uppercase letters and digits, so a QR code
can encode them in alphanumeric mode, and typed entry tolerates lowercase,
spaces, and hyphens. The issuer must be an active manager.

The lifetime resolves at issue time:

1. An explicit `ExpiresAt` on the request.
2. Else, for a reusable token, the client's `login_token_ttl`; else the
   deployment's `login_token_ttl` (30 days by default).
3. Else, for a single-use token, `single_use_token_ttl` (20 minutes by
   default).
4. Never beyond `login_token_max_ttl` (400 days by default); longer
   requests are clamped and the clamp is logged.

The 30-day default suits a general SaaS platform; a learning application
typically sets a term or a school year on its client.

### Exchanging a Token

The application posts the token to SystemAuth:

```http
POST /login-token
Content-Type: application/x-www-form-urlencoded

token=SFLT...&client_id=learning-app&return_to=/play
```

On success SystemAuth establishes its usual login session cookie and
answers `303 See Other` to `return_to` (checked against the redirect
allowlist) or the default target. The authorization-code flow then proceeds
as for any signed-in user.

The exchange replaces the browser's login session, so it accepts only a form
posted from a page on the issuer's origin or one of
`social_login.allowed_redirect_origins`, judged by the `Origin` header (or
`Referer`). A post from any other site, or with neither header, receives
`403`; an application that hosts the sign-in form on its own origin lists that
origin in `allowed_redirect_origins`.

Unknown, malformed, expired, revoked, and used tokens, a client that does
not allow managed principals, and an inactive principal all receive the
same `401`. The endpoint is rate limited per source address (60 a minute
by default, enough for a class signing in from one network) and per client
(600 a minute); configure shared storage with
`systemauth.WithLoginTokenRateLimit` when several instances serve it. A
single-use token succeeds at most once, even when presented concurrently.

### Claims

ID tokens and `userinfo` for a managed principal carry `"managed": true`,
whatever scopes were granted, and omit `email` and `email_verified` when
the principal has no email. Relying parties read it into
`relyingparty.VerifiedIdentity.Managed`; the relying-party layer creates a
managed principal locally on its first sign-in and never links one by
email, so an application's `PrincipalStore.CreatePrincipal` must accept an
identity with or without an email when `Managed` is set.

## Ending and Entering Management

`Release` ends management of a principal with a verified email: its
managers are removed and its default human capabilities restored, as one
audited event. Without a verified email it returns `ErrEmailNotVerified`;
removing the last manager of a principal with one has the same effect.

```go
err := svc.Release(ctx, guardianID, studentID) // needs manage_managers
```

A self-managed human enters management only by consent. A prospective
manager invites its verified address, and the person accepts while signed
in:

```go
inv, err := svc.InviteManager(ctx, managedprincipal.InviteManagerInput{
    ClientID: "match-app", ManagerID: familyMemberID,
    Email: "adult@example.com", Role: managedprincipal.RoleGuardian,
})
// deliver inv.Token; then, as the signed-in invitee:
managerID, err := svc.AcceptManagerInvite(ctx, token, signedInPrincipalID)
```

An invitation is single use, expires after seven days, and matches only a
principal whose verified email is the invited address.

## Authorization and the HTTP API

Every service operation consults the authorizer, so a Go caller and the
HTTP handler are held to the same rules:

| Operation | Needs |
|-----------|-------|
| `Create` | The actor is the only named manager, or a platform administrator; other managers need `WithDirectManagerAdds` |
| `AddManager` | `WithDirectManagerAdds`, and `manage_managers` (guardians) |
| `RemoveManager`, `Release` | `manage_managers` (guardians) |
| `Delete`, `AttachVerifiedEmail` | `manage_account` (guardians) |
| `IssueClaim`, `IssueLoginToken`, tokens, sessions | `manage_credentials` (guardians, educators); a role registered with `WithRoles` cannot issue a login token |
| `RedeemClaim` | A valid manager claimant, and an issuer that still holds `manage_credentials` |

`Delete` deactivates the principal and erases what identifies or
authenticates the person (email, names, credentials, sessions, consents),
keeping the row so identifiers elsewhere keep resolving; data the
application keeps is its own to remove.

`managedprincipal.NewHandler(svc)` serves the same operations as JSON; see
the route list in the
[architecture page](../design/architecture/managed-principals.md#sessions-and-manager-visibility).

## Relying Parties: the API on SystemAuth

When a host builds SystemAuth with `systemauthsvc` and enables managed
principals, SystemAuth serves the API to applications composed beside it,
in the same process or another, at `/managed-principals`
(`systemauthsvc.ManagedPrincipalsPath`). The principals stay in SystemAuth's
database; an application keeps only their IDs.

Each call carries the signed-in manager's SystemAuth access token, granted
the `systemforge:managed_principals` scope (`managedprincipal.Scope`). The
manager is the actor, and the application is the client the token was
issued to: that client must allow managed principals, and a body naming
another client is refused. Give the client the scope and the opt-in:

```yaml
managed_principals:
  enabled: true

clients:
  - id: learning-app
    managed_principals: true
    scopes: [openid, profile, email, systemforge:managed_principals]
```

The API differs from the in-process handler in a few ways:

- **Creation** names only the caller as manager, by `role`. Further managers
  join with their consent, through an invitation or a claim;
  `POST /{id}/managers` is refused.
- **One answer for strangers.** An unknown principal, one that is not
  managed, and one the caller does not manage all answer 403, so the API
  cannot be asked who is a managed principal.
- **Codes are rate limited** per caller: 10 a minute by default across claim
  redemption and invitation answers (`managedprincipal.DefaultCodeLimit`).
  Pass shared storage in `systemauthsvc.Options.ManagedPrincipalRates` when
  several instances serve SystemAuth.
- **No email attachment.** A relying party cannot prove an address belongs to
  the principal, so `AttachVerifiedEmail` stays an in-process operation.

`systemauthsvc.Options.AuditEmitter` records every write, and
`Options.ManagedPrincipalOptions` passes roles, an authorizer or an authz
syncer to the service. A host in the same process can call
`Service.ManagedPrincipals()` directly.

Applications call the API with `managedprincipal/mpclient`, which depends on
the standard library and `uuid` only:

```go
// rp is the application's relyingparty.Client: its Transport presents the
// manager's DPoP-bound session token with a proof by the application's key.
mp := mpclient.New("https://auth.example.com/managed-principals",
    &http.Client{Transport: rp.Transport(nil)})

id, err := mp.Create(ctx, managerToken, mpclient.CreateInput{
    DisplayName: "Robin",
    Role:        mpclient.RoleEducator,
})
card, err := mp.IssueLoginToken(ctx, managerToken, id, mpclient.IssueLoginTokenInput{Name: "Robin's card"})
// card.Token is shown once; render it as a QR code or a printed card.
```

SystemAuth binds the tokens it issues to the requesting client's DPoP key
and refuses a bound token sent as `Bearer`. `mpclient` sets the token as
`Bearer`; `relyingparty.Client.Transport` presents a token bound to the
relying party's key with the `DPoP` scheme and a proof, and an unbound one
(from a client registered with `allow_bearer_tokens`) unchanged. A reverse
proxy that forwards the manager's calls to the API uses the same transport.
Without it, a bound token answers `ErrUnauthorized`.

Errors match `mpclient.ErrUnauthorized`, `ErrForbidden`, `ErrNotFound`,
`ErrInvalidCode`, `ErrInvalidRequest`, `ErrConflict`, and `ErrRateLimited`
with `errors.Is`, and unwrap to `*mpclient.APIError` for the status, message
and `RetryAfter`. The managed principal then signs in at
`POST /login-token` as described in [Exchanging a Token](#exchanging-a-token).

## Manager Visibility and Revocation

Managers holding `manage_credentials` can see and end every way a managed
principal is signed in:

| Method | Covers |
|--------|--------|
| `ListLoginTokens`, `RevokeLoginToken` | Live login tokens, never their values |
| `ListSessions`, `RevokeSession` | Browser login sessions, OAuth token families, principal token families |
| `RevokeAll` | All of the above, in one transaction |

Revoking a token family revokes all its tokens, so a refresh token cannot
renew it. `managedprincipal.NewHandler` serves these as JSON for the
manager identified by `requestprincipal`:

```go
router.With(requestprincipal.Middleware(opts, authenticators...)).
    Mount("/managed-principals", managedprincipal.NewHandler(svc))
```

```text
GET    /managed-principals/{id}/login-tokens
POST   /managed-principals/{id}/login-tokens
DELETE /managed-principals/{id}/login-tokens/{credentialID}
GET    /managed-principals/{id}/sessions
DELETE /managed-principals/{id}/sessions/{kind}/{sessionID}
POST   /managed-principals/{id}/revoke-all
```

Permissions are checked through an `authz.Authorizer`. The default is the
simple provider backed by the service's `ManagerRoles`; pass
`managedprincipal.WithAuthorizer` to use SpiceDB or to add a
platform-administrator check.

## Claiming a Managed Principal

A teacher often creates the account before any parent is involved. A
manager with `manage_credentials` issues a **claim**, a single-use code
handed to the parent on paper or as a QR code:

```go
claim, err := svc.IssueClaim(ctx, teacherID, learnerID)
// claim.Code is shown once; claim.ExpiresAt is seven days out by default.

learnerID, err = svc.RedeemClaim(ctx, code, parentID)
// The parent is now a guardian of the learner.
```

The claimant must be an active human with an email who is not managed.
Claims are stored hashed in their own table, apart from credentials, so a
claim code can never sign anyone in. `WithClaimTTL` changes the lifetime.

## Attaching an Email

When a managed principal is ready for its own account, a guardian attaches
an email:

```go
err := svc.AttachVerifiedEmail(ctx, parentID, learnerID, "robin@example.com", verifiedAt)
```

The email becomes the identifier and default human capabilities are
restored, so the principal can set a password and manage its own profile.
Manager relationships remain until removed, and now the last one may be.
The caller must have verified that the principal controls the address.

## Authorization

The base SpiceDB schema defines:

```zed
definition principal {
    relation guardian: principal
    relation educator: principal

    permission manage_account     = guardian
    permission manage_credentials = guardian + educator
    permission view_profile       = guardian + educator
    permission manage_managers    = guardian
}
```

With `WithAuthzSyncer`, every relationship change is written to the
authorization backend: removals inside the transaction, before the commit,
so a backend failure leaves the manager in place and is returned; additions
after the commit. The simple provider stores nothing; configure it
with `simple.WithManagerRoleGetter(svc.ManagerRoles)` and it applies the
same table, so both providers agree.

Applications add domain permissions in their own definitions, for example
a learner's progress record, which the learner's managers and the
organization's administrators may view:

```zed
definition learning_progress {
    relation learner: principal
    relation org: organization
    permission view = learner->view_profile + org->manage
}
```

## Other Surfaces

| Surface | Behavior |
|---------|----------|
| Password and social login | A missing email never matches; managed principals have no password until an email is attached |
| Invitations and signup | Target an email; they never create managed principals |
| SCIM | Managed principals are not SCIM users: they are not listed, changed, or grouped through SCIM |
| Marketplace | `stripe.WithPurchaserChecker(svc)` refuses checkout with `marketplace.ErrManagedPurchaser`; billing is a guardian's action |

## Application Responsibilities

SystemForge supplies a manager with the authority to consent and delete. It
does not record consent, ages, or regulatory evidence; the application
records what its jurisdiction requires.
