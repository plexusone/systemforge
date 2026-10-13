# ADR-016: No Static API Keys — OAuth Grants for Non-Interactive Access

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-007 (memberships and entitlements as claims), ADR-010
(real-time access invalidation), ADR-015 (identifier policy; credentials are
CSPRNG secrets, never identifiers).
**Updates:** `docs/design/architecture/authentication.md` (non-interactive
access).

## Context

Applications on SystemForge have offered long-lived API keys for the cases
a browser session does not cover: a command-line tool, an MCP server, a
script, a CI job. An API key is a static bearer secret, and its
authorization has to come from somewhere:

- **From the key itself** (a role recorded at creation, or claims inside a
  JWT key): the role is frozen when the key is minted. Removing a person
  from an organization does not reach a key that outlives the access-change
  window, because ADR-010's revocation cache keeps entries only for the
  access-token lifetime.
- **From a lookup on every request:** every application then needs its own
  membership source for keys, which ADR-007 decision 10 removes, and every
  key check becomes a database or network call.

Both make the key a second, weaker authorization path beside the token
path every application already verifies. Security reviews also treat
long-lived static secrets as a finding to be justified.

SystemAuth already issues short-lived JWT access tokens carrying the `orgs`
claim, rotates refresh tokens on every use, revokes the token family when a
used refresh token is presented again, and bounds a family's absolute
lifetime.

## Decision

1. **SystemForge offers no static API keys.** Every non-interactive caller
   holds a credential that it exchanges at SystemAuth's token endpoint for a
   short-lived access token. Applications verify access tokens only; there
   is one authentication path, and the `orgs` claim in it is always current
   to within one token lifetime.

2. **The grant depends on who is calling.**

   | Caller | Grant | What the caller holds |
   |---|---|---|
   | A person at a terminal (CLI, MCP) | Authorization code with PKCE and a loopback redirect (RFC 8252), then refresh tokens | A refresh token: rotated on use, revoked as a family on reuse, bound to the client, with an absolute lifetime |
   | A person on a host without a browser | Device authorization grant (RFC 8628) | The same refresh token |
   | Automation holding a key pair (servers, scripts) | Client credentials, authenticated with `private_key_jwt` (RFC 7523 section 2.2) | A private key; SystemAuth stores only the public key |
   | CI and cloud workloads with their own identity | JWT bearer grant (RFC 7523 section 2.1) trusting the platform's token, such as GitHub Actions OIDC | Nothing stored: the platform issues the assertion per run |
   | AI agents | AAuth (agent, resource and mission tokens) | The agent's key; unchanged by this ADR |

3. **Client credentials never use a shared secret in production.** A
   `client_secret` for the client credentials grant is a static API key by
   another name. Confidential clients that call it authenticate with
   `private_key_jwt` or through federation; `client_secret_basic` and
   `client_secret_post` remain only for web relying parties completing an
   authorization code flow, and for development.

4. **Automation acts as a service principal in an organization.** A client
   used for client credentials or the JWT bearer grant is owned by an
   organization and represented by a service principal that holds
   application roles there (ADR-007), assigned like a person's. Its access
   tokens carry an `orgs` claim with that one organization, so applications
   authorize it exactly as they authorize people. A client's access ends
   when its roles are removed or the client is disabled, through the same
   access-change records (ADR-010).

5. **Refresh tokens for people keep the existing policy:** rotation on use,
   family revocation on reuse, an absolute lifetime (default 30 days), and
   revocation at sign-out. Native clients store them in the operating
   system's credential store where one exists.

6. **Migration.** Applications remove their API-key routes, tables and
   checks. Tools that sent a static bearer token gain a login command using
   decision 2's grant for their caller.

## Consequences

- **One way in.** Applications verify JWT access tokens and AAuth requests,
  nothing else; there is no per-application key table to secure, rotate or
  audit.
- **Current authorization everywhere.** A role change reaches every caller
  within one access-token lifetime, or at once through the revocation
  cache.
- **No server-side secrets for automation.** SystemAuth keeps public keys
  and federation trust, not shared secrets.
- **Every token issuance is an auditable event,** at one place.
- **Command-line tools must implement a login** (loopback browser flow,
  later device flow) instead of reading a key from the environment, and
  until they do, those tools cannot reach a hosted deployment.
- **Service principals in organizations are new work** (decision 4): today
  a client-credentials token has no `orgs` claim.

## Alternatives considered

- **Opaque API keys checked by each application.** Rejected: a second
  authorization path, per-application tables, and stale roles unless every
  check calls SystemAuth.
- **API keys as long-lived JWTs carrying claims.** Rejected: claims frozen
  at minting, outliving the revocation cache, readable by anyone holding the
  key, and all invalidated by a signing-key rotation.
- **Opaque API keys exchanged for access tokens (RFC 8693 token
  exchange).** Workable, but it keeps a static secret where a refresh token
  (people) or a key pair or federation (automation) does the same job with
  standard grants and no stored secret.
- **Client credentials with a client secret.** Rejected for production by
  decision 3: it is a static key.

## Open questions

- Whether the device authorization grant is built on the current OAuth
  library or waits for a version that includes it.
- How a federation trust maps an external subject (a repository and
  workflow, a cloud service account) to a service principal, and who in an
  organization may create one.
- Whether a person may create a service principal in an organization, or
  only owners and admins.
