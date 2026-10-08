# Humans

A person is a **human principal**: a row in `sf_principals` with `type = human`, joined one-to-one with its `sf_humans` extension. There is no separate user table. Every sign-in method (password, social login, federation sync, SCIM) resolves to the same human principal, so one person has one identity.

## Schema

`sf_principals` holds what every principal type shares:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key, used as the subject (`sub`) in tokens |
| `type` | enum | `human`, `application`, `agent`, or `service` |
| `identifier` | string | Unique lookup key: the email for humans, or `human:<id>` for a managed principal |
| `display_name` | string | Human-readable name |
| `organization_id` | UUID | Optional owning organization |
| `active` | bool | Whether the principal can authenticate |
| `capabilities` | JSON | Principal capabilities |
| `allowed_scopes` | JSON | Scopes the principal may request |
| `metadata` | JSON | Custom metadata |
| `created_at`, `updated_at` | time | Timestamps |

`sf_humans` holds the human-specific fields:

| Field | Type | Description |
|-------|------|-------------|
| `principal_id` | UUID | The owning principal |
| `email` | string | Primary email address; null only for a [managed principal](managed-principals.md) |
| `given_name`, `family_name` | string | Name parts |
| `avatar_url` | string | Profile picture URL |
| `locale`, `timezone` | string | Preferences |
| `is_platform_admin` | bool | Cross-organization admin access |
| `last_login_at` | time | Last successful login |
| `email_verified_at` | time | When the email was verified |

Related records:

- **Passwords** are rows in `sf_credentials` with type `password` (Argon2id hashes).
- **Upstream logins** (GitHub, Google, a federation hub) are rows in `sf_external_identities`, keyed by provider and subject.
- **Organization memberships** are rows in `sf_principal_memberships`; see [Memberships](memberships.md).

## Creating Humans

Use the principal service, which creates the principal and its human extension in one transaction:

```go
import "github.com/plexusone/systemforge/identity/principal"

principals := principal.NewService(client)

p, err := principals.CreateHuman(ctx, principal.CreateHumanInput{
    Email:       "user@example.com",
    DisplayName: "Jane Doe",
    GivenName:   "Jane",
    FamilyName:  "Doe",
})
if err != nil {
    return err
}
// p.ID is the principal ID; p.Human holds the extension fields.
```

### Setting a Password

```go
import "github.com/plexusone/systemforge/identity/credential"

creds := credential.NewService(client)

err := creds.CreatePassword(ctx, credential.CreatePasswordInput{
    PrincipalID: p.ID,
    Password:    password,
})
```

`VerifyPassword` and `UpdatePassword` on the same service check and rotate it. A human without a password credential signs in only through an upstream provider.

## Email Requirement

Every human has an email unless it is a **managed principal**: a human whose
account is created and controlled by managers with an email, enabled per
deployment and per client. Every creation path documented here (the
principal service, SystemAuth storage, signup, SCIM, social login, and
federation sync) refuses a human without an email; managed principals are
created only through `identity/managedprincipal`. See
[Managed Principals](managed-principals.md).

The identifier is a lookup key, not an address: never send mail to it.

## Email Uniqueness

Emails are unique **ignoring case**. Lookups by email are case-insensitive, and SystemAuth's storage rejects a create or update whose email differs only in case from another human's, so `Ada@Example.com` and `ada@example.com` cannot both exist.

## Querying Humans

### By ID or Email

```go
p, err := principals.GetByID(ctx, principalID)

// The identifier of a human principal is its email.
p, err = principals.GetByIdentifier(ctx, "user@example.com")
```

### With Ent Directly

```go
import (
    "github.com/plexusone/systemforge/identity/ent/human"
    entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
)

p, err := client.Principal.Query().
    Where(
        entprincipal.TypeEQ(entprincipal.TypeHuman),
        entprincipal.HasHumanWith(human.EmailEqualFold("user@example.com")),
    ).
    WithHuman().
    Only(ctx)
```

## Updating Humans

```go
name := "Jane Smith"
family := "Smith"

p, err := principals.UpdateHuman(ctx, principalID, principal.UpdateHumanInput{
    UpdateInput: principal.UpdateInput{DisplayName: &name},
    FamilyName:  &family,
})
```

`Deactivate` and `Reactivate` toggle `active`; a deactivated principal cannot authenticate.

## SystemAuth Storage

The SystemAuth server works with humans through its `Storage` interface using one value type, `systemauth.HumanPrincipal`, which joins a human principal with its extension:

| Method | Purpose |
|--------|---------|
| `CreateHuman(ctx, h)` | Create a human; assigns `h.ID` when it is `uuid.Nil` |
| `GetHuman(ctx, id)` | Look up by principal ID |
| `GetHumanByEmail(ctx, email)` | Look up by email, ignoring case |
| `GetHumanByExternalIdentity(ctx, provider, subject)` | Look up through a linked upstream identity |
| `LinkExternalIdentity(ctx, principalID, provider, subject)` | Link an upstream identity; relinking the same pair is a no-op |
| `UpdateHuman(ctx, h)` | Replace the profile fields |
| `DeleteHuman(ctx, id)` | Delete the human with its extension, external identities, and credentials |

Not-found lookups return `systemauth.ErrPrincipalNotFound`; a taken email returns `systemauth.ErrPrincipalExists`; an upstream identity already linked to another human returns `systemauth.ErrExternalIdentityExists`. Both `systemauth.NewEntStorage` and `systemauth.NewMemoryStorage` implement these methods.

### Password Login

Password login uses an injectable verifier. Because identity IDs are principal IDs, the credential service's `VerifyPassword` plugs in directly:

```go
creds := credential.NewService(client)

providers := systemauth.NewProvidersFromStorage(
    systemauth.NewEntStorage(client),
    systemauth.WithProviderPasswordVerifier(creds.VerifyPassword),
)

session, err := providers.Authentication.Authenticate(ctx, &systemauth.AuthenticateRequest{
    Method:     systemauth.AuthMethodPassword,
    Identifier: "user@example.com",
    Password:   password,
})
```

A person who first signed in with a social provider and later sets a password authenticates as the same principal.

### Federation Sync

Identities synced from a federation hub are linked as external identities with the provider `systemauth.FederationProvider` and the federation identity ID as the subject. Creating an identity whose email already exists links the existing human instead of creating a second one.

## Platform Admins

`is_platform_admin` on the human extension grants cross-organization access:

```go
admin := true
_, err := principals.UpdateHuman(ctx, principalID, principal.UpdateHumanInput{
    IsPlatformAdmin: &admin,
})
```

## Edges

A human principal relates to:

| Edge | Target | Description |
|------|--------|-------------|
| `human` | Human | Human extension |
| `credentials` | Credential | Passwords, API keys, keypairs |
| `external_identities` | ExternalIdentity | Linked upstream logins |
| `principal_memberships` | PrincipalMembership | Organization memberships |
| `principal_tokens` | PrincipalToken | Issued tokens |
| `owned_organizations` | Organization | Personal organizations |
| `owned_oauth_apps` | OAuthApp | OAuth apps it owns |
| `oauth_consents` | OAuthConsent | Consent grants |
