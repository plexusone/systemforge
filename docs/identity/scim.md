# SCIM Provisioning

`identity/scim` serves SCIM 2.0 (RFC 7643/7644) so an enterprise identity
provider such as Okta or Microsoft Entra ID can provision users. The Ent store
(`identity/scim/store`) maps SCIM Users to human principals and SCIM Groups to
organizations.

## Credentials Are Bound to an Organization

Every SCIM request runs in a provisioning scope. The store refuses any
request without one (403), so a credential must be bound to exactly one
organization, or explicitly to the platform.

## Tenant SCIM Tokens

`identity/scim/scimtoken` stores the bearer tokens tenants give their
identity providers, one set per organization, and authenticates SCIM
requests with them:

```go
tokens := scimtoken.New(client,
    scimtoken.WithAuthorizer(authorizer),    // who may manage tokens
    scimtoken.WithAuditEmitter(auditEmitter), // optional
)

api, err := scim.NewAPI(provider) // provider config BaseURL "/scim/v2"
if err != nil {
    return err
}
h := api.CredentialMiddleware(tokens.CredentialFunc(scimtoken.CredentialOptions{}))(api)
router.Handle("/scim/v2", h)
router.Handle("/scim/v2/*", h)
```

The API serves its routes under the provider's `BaseURL`, so handle that
path on the router rather than mounting the API under a stripped prefix.
`CredentialFunc` binds the token's organization as the tenant
(`scim.WithTenant`), grants `scim.ScopeFull` (set
`CredentialOptions.Scopes` to narrow it), and answers `401` for a missing,
malformed, unknown, revoked, expired or superseded token. With
`identity/systemauthsvc`, setting `Options.SCIM` does all of this at
`/scim/v2`.

### Token format

A token is `sfscim_` followed by 49 base62 characters: 256 random bits
(43 characters) and a CRC-32 checksum of them (6 characters). Secret
scanners can match `sfscim_[0-9A-Za-z]{49}` and confirm a match with the
checksum. Only a SHA-256 hash of the token and a display prefix (`sfscim_`
and 8 more characters) are stored; the plaintext is returned once, when
the token is issued. Treat a token like a password: it provisions and
deprovisions the organization's members.

### Issue, rotate and revoke

| Call | Effect |
|------|--------|
| `Issue(ctx, actor, orgID, opts)` | Issues the organization's first token. Fails with `ErrTokenExists` if it already holds a valid one |
| `Rotate(ctx, actor, orgID, opts)` | Issues a new current token N, keeps the previous token N-1 valid, and revokes N-2 and older in the same transaction |
| `Revoke(ctx, actor, orgID, tokenID)` | Revokes one token. Revoking N ends the overlap early, or rolls back a bad N: N-1 becomes current again |
| `List(ctx, actor, orgID)` | Token metadata, newest first, with a status: `current`, `previous`, `revoked`, `expired` or `superseded` |
| `Authenticate(ctx, token)` | The token's organization, if the token is one of the organization's two newest unrevoked, unexpired tokens and the organization is active |

Rotation never drops N-1 in the step that issues N, so switching the
identity provider to N can be undone. A typical rotation:

1. `Rotate`, and configure the identity provider with the new token.
2. Watch provisioning succeed. If it fails, `Revoke` the new token; the
   provider's previous token is current again.
3. Leave N-1 to be revoked by the next rotation, or `Revoke` it once the
   switch is confirmed.

`IssueOptions.ExpiresIn` bounds a token's lifetime; by default tokens do
not expire. Concurrent rotations of one organization cannot leave three
valid tokens: a unique (organization, generation) index lets only one of
them commit, and the other returns `ErrConflict`. A token's last use is
written at most once a minute (`WithLastUsedInterval`), not on every
request.

### Who may manage tokens

`Issue`, `Rotate`, `Revoke` and `List` require the acting principal to
hold `authz.PermOrgSettings` on the organization (its owners and
admins) or, when the authorizer implements `authz.PlatformAuthorizer`, to
be a platform administrator. Without `WithAuthorizer` every management
call is refused.

`scimtoken.NewAPI` serves the same operations over HTTP, beside the
organization API:

| Method | Path | Operation |
|--------|------|-----------|
| `GET` | `/api/v1/organizations/{slug}/scim-tokens` | List |
| `POST` | `/api/v1/organizations/{slug}/scim-tokens` | Issue (`{"description", "expires_in_seconds"}`) |
| `POST` | `/api/v1/organizations/{slug}/scim-tokens/rotate` | Rotate |
| `DELETE` | `/api/v1/organizations/{slug}/scim-tokens/{token_id}` | Revoke |

Responses carry `Cache-Control: no-store`. `systemauthsvc` serves this API
for access tokens granted `systemforge:scim_tokens`
(`systemauthsvc.SCIMTokensScope`), and `Service.SCIMTokens` returns the
store for operator commands.

### Audit

With `WithAuditEmitter`, the store records `scim_token.issued`,
`scim_token.rotated` (with the IDs of the tokens it revoked),
`scim_token.revoked`, and `scim_token.authentication_failed` (with a
reason, and the client address and user agent when authenticated through
`CredentialFunc`). Events name tokens by ID and display prefix, never by
the token or its hash.

### Custom token stores

An application that keeps its own SCIM credentials can still pass any
function to `CredentialMiddleware`, returning a `scim.Credential` whose
`Scope` names the organization. If it rotates tokens, it should keep the
same rule: issuing N leaves N-1 valid and revokes only N-2 and older.

## What a Tenant Credential Can Do

A credential bound to an organization manages that organization's members:

| Operation | Behavior |
|-----------|----------|
| List or get users | Only members of the organization, active or suspended |
| Create a user | Creates the user and makes them a member. If the email already belongs to a user, that user is added as a member and their identity is unchanged |
| Update a user | `active` suspends or restores the membership. Email, name and photo change only for users the organization owns |
| Delete a user | Removes the membership; deletes the account only when the organization owns it |
| Groups | The organization is the only group. Members can be added and removed; the group cannot be created, renamed or deleted |

An organization **owns** a user it provisioned who belongs to no other
organization. A user who also belongs elsewhere, such as a person with a
personal account or a member of another organization, is shared: the
organization's identity provider manages only their membership, so it cannot
change a login email used elsewhere.

## Membership Changes

The store changes memberships only through the organization service, so a
SCIM change has the same effects as any other: the authorization graph is
synced, an access change is recorded so existing tokens stop being honored,
and a removed member's application roles and resource grants go with the
membership. Pass the application's configured services:

```go
st := store.NewEntStore(client, &store.Config{
    BaseURL:     "/scim/v2",
    DefaultRole: "member",
    Memberships: orgService,       // organization.Service with the authz syncer
    Principals:  principalService, // principal.Service
})
```

Without them the store builds services on its Ent client: access changes are
still recorded, but no authorization graph is synced, which a SpiceDB
deployment needs.

Two rules apply on top:

- An organization owner is never suspended, removed or deleted through SCIM
  (403), so an identity provider cannot lock a customer out of its own
  organization. Transfer ownership first.
- A restored membership (`active` back to true, or re-adding a removed member
  to the group) gets the default role, not the role it had before, because
  the identity provider does not manage roles.

Creating a user adds the account first and the membership after. If adding
the membership fails, the request fails; the identity provider's retry finds
the account by email and links it.

## Passwords

A password sent on create, PUT or PATCH is hashed with the provider's
`PasswordHasher` (bcrypt by default) before it reaches the store, so a custom
`Store` only ever receives a hash. A PATCH that does not set a password hands
the store the stored value unchanged. Passwords, and their hashes, are never
returned in a response. The Ent store does not persist SCIM passwords; users
it provisions sign in through the application's own login methods.

## Filters

The Ent store evaluates `filter` on these attributes, and answers `400
invalidFilter` for anything else (another attribute, an operator the
attribute does not support, a value of the wrong type, a value-path filter
such as `emails[type eq "work"]`, trailing input, or nesting deeper than
`filter.MaxDepth`), so a filter never returns more resources than it names:

| Resource | Attributes |
|----------|------------|
| Users | `id`, `userName` and `emails.value` (case-insensitive), `displayName` and `name.formatted`, `active` (`eq`, `ne`), `meta.created` and `meta.lastModified` (`gt`, `ge`, `lt`, `le`), `externalId` (`eq`, `pr`; users carry none, so it matches nobody) |
| Groups | `id`, `displayName`, `externalId` (the organization slug), `meta.created`, `meta.lastModified` |

## Request Limits

- `/Bulk` accepts at most `Config.BulkMaxOperations` operations and a body
  of at most `Config.BulkMaxPayloadSize` bytes (413 beyond it); both are
  advertised in `ServiceProviderConfig`.
- At most `Config.BulkMaxPasswordOperations` operations in one bulk request
  may set a password (default 50; a negative value refuses passwords in
  bulk), because each one costs a password hash.
- A filter may nest at most `filter.MaxDepth` levels.
- List pages load group memberships in one query when the store implements
  `scim.BatchMembershipStore`, as the Ent store does, instead of one query
  per returned user or group.

## Errors

A database or other unexpected error is logged with the API's logger and
answered with a generic `500` whose detail is `internal error`, so SQL,
driver and schema text never reaches the identity provider. A custom store
should return `scim.InternalError(ctx, err)` for such errors and a
`*scim.Error` for anything the client can act on. Likewise, an error from
the credential function given to `CredentialMiddleware` is logged and
answered with a generic `401`, unless it is a `*scim.Error`, which is
returned as it is.

## Platform Operator Credentials

A credential with `scim.Scope{Platform: true}` provisions every user and
organization, as SCIM did before scoping. For it, `active` deactivates or
reactivates the account itself. Issue it only to platform operators,
never to a customer's identity provider.

Tenant tokens are never platform credentials. To accept platform
credentials next to them, set `CredentialOptions.Platform` (or
`systemauthsvc.SCIMOptions.PlatformCredential`): it is called only for
bearer tokens that are not tenant tokens, and a credential it returns
without `Scope.Platform` is refused.

A platform credential also manages organizations as groups, through the
organization service (`store.Config.Organizations`, by default the
`Memberships` service when it is a full `organization.Service`):

- Creating a group creates a team organization. Its slug is the group's
  `externalId`, which must be a valid organization slug (3 to 63 lowercase
  letters, digits and hyphens, starting with a letter), not reserved, not
  taken and not in another organization's cooling-off period; without an
  `externalId` the slug is generated from `displayName`.
- Deleting a group soft-deletes the organization, as an administrator's
  delete does: it is removed from the authorization graph and no longer
  listed, and its memberships and history are kept.
- A personal organization belongs to its owner: it cannot be renamed or
  deleted through SCIM (403).
