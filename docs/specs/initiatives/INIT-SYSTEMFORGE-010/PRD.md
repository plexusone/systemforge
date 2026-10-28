# PRD — Service Accounts with Key-Pair Credentials

**Initiative:** `INIT-SYSTEMFORGE-010`
**Status:** Draft
**Home repo:** `github.com/plexusone/systemforge`
**Target release:** v0.26.0, with `INIT-SYSTEMFORGE-014`
**Implements:** ADR-016 decisions 1, 2 (automation holding a key pair) and 4

## Problem

ADR-016 removes static API keys: every non-interactive caller exchanges a
credential at SystemAuth for a short-lived access token. A person at a
terminal already can, through `identity/publicclient`. Automation that runs
without a person cannot. Examples:

- a CI job that publishes on merge;
- a scheduled import;
- an agent running on a server.

Today such automation has two options, and both are what ADR-016 rules out:

- **The client-credentials grant with a client secret.** This is a static
  secret by another name. Its token's subject is the client, not a
  principal, so it carries no `orgs` claim, and applications cannot
  authorize it the way they authorize people.
- **An application's own API keys.** These are a second authentication path,
  with a role frozen when the key was made.

Applications on SystemForge are therefore keeping API keys for exactly this
case.

The parts exist but are not connected:

- `principal.CreateService` makes a service principal.
- `identity/credential` stores key-pair credentials with a key ID,
  algorithm, public key, scopes, expiry and revocation.
- `clientassertion.JTIStore` records used assertion IDs.
- Application roles and memberships produce the `orgs` claim for any
  principal ID.
- SystemAuth binds every token it issues to a DPoP key.

What is missing:

- the token grant;
- a service account that belongs to an organization and holds roles there;
- commands to manage one;
- a client that uses one;
- applications accepting its tokens, since a service principal never signs
  in and so has no local record.

## Goals

1. **A service account belongs to one organization.** It is created there,
   holds application roles there like a member, and its tokens carry an
   `orgs` claim with that organization.
2. **It authenticates with a private key it never shares.** It signs a
   short-lived assertion, and SystemAuth verifies it with the registered
   public key (the RFC 7523 JWT-bearer grant). SystemAuth stores only public
   keys.
3. **Its tokens are short-lived and DPoP-bound,** with no refresh token. The
   account signs a new assertion when a token expires.
4. **Access ends through the usual paths:**
   - removing a role, disabling the account, or revoking a key;
   - each recorded as an access change (ADR-010), so applications drop it
     within one token lifetime or at once through the revocation cache.
5. **Operators manage accounts with commands:**
   - create, list, disable, enable and delete accounts;
   - add, list and revoke keys;
   - grant and remove roles.
6. **A Go client** that turns a private key file into an `http.Client` which
   calls an API: it signs assertions, adds proofs and renews tokens.
7. **Applications accept service-account tokens** through
   `identity/relyingparty` and `identity/appauth`, creating the account's
   local record on first use.

## Non-Goals

- **Assertions from other issuers** (workload identity federation, such as
  GitHub Actions OIDC). This release accepts self-issued assertions only.
  ADR-016 lists federation as a separate grant, and a trusted-issuer
  registry is a follow-on.
- **An HTTP API and pages for organization admins.** Commands cover
  operators first. The organization console can add pages over the same
  service later.
- **Refresh tokens** for service accounts.
- **Human principals using this grant.**
- **Agents using this grant.** AI agents keep AAuth, as ADR-016 says.
- **Removing client credentials with a secret.** It stays for development
  and existing deployments. ADR-016 decision 3 restricts it in production
  separately.

## Users

| User | Needs |
| --- | --- |
| Operator | Create a service account in an organization, give it roles, register its public key, rotate and revoke keys, disable it, see when each key was last used |
| Workload developer | A private key file and a client ID-like account identifier, and a Go client that does the rest |
| Application developer | Service-account requests arrive like any other, as a principal with memberships, with no new code beyond one option |
| Security reviewer | No stored secrets, short assertions, replay protection, DPoP binding, and access that ends with the role |

## Requirements

### SystemAuth

- **F1. Account in an organization.**
  - A service account is a service principal whose `organization_id` is its
    organization.
  - It has an active membership there with the role `service_account`
    (shown as "Service account"), and it holds application roles there
    through `approle`. Its principal type stays `service`.
  - Creating one records who created it.
- **F2. The grant.** The token endpoint accepts
  `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and verifies the
  assertion's signature with the key-pair credential named by its `kid`.
- **F3. Assertion rules:**
  - `iss` and `sub` both equal the account's identifier, and the key belongs
    to the account;
  - `aud` names the token endpoint or the issuer;
  - `exp`, `iat` and `jti` are required;
  - the lifetime is at most a configured maximum (default five minutes).
- **F4. No replay.** A used `jti` is refused until the assertion would have
  expired.
- **F5. Usable keys only.** The key must be active, unexpired and unrevoked;
  the account active and of type service; its organization active.
- **F6. Scopes** are the requested scopes intersected with the key's scopes
  and the account's allowed scopes.
- **F7. DPoP required.** The token request must carry a DPoP proof, and the
  token is bound to the proof's key. The bearer exception does not apply to
  this grant.
- **F8. The token:**
  - its subject is the account's principal ID;
  - it carries the `orgs` claim and `principal_type: "service"`;
  - its lifetime is configured (default 15 minutes);
  - no refresh token is issued.
- **F9. Last use.** Each exchange records the key's last-used time and
  address.
- **F10. Ending access.** Each of these records an access change:
  - disabling the account (`Deactivated`, which also sends back-channel
    logout);
  - deleting it;
  - removing a role;
  - revoking its last key.
- **F11. Off by default.** The grant is disabled unless configured.
  Discovery advertises it only when enabled.

### Commands

- **F12.** `service-account create|list|show|disable|enable|delete`, as
  cobra commands a host mounts (like the sign-up commands) and that
  `cmd/systemauth` registers. They open the identity database directly,
  so they need the host's shell; operators are the people who run the
  deployment.
- **F13.** `service-account key add|list|revoke`:
  - `key add` generates a P-256 key pair, stores the public key and writes
    the private key once to a file only the owner can read;
  - or it registers a public key the operator supplies.
- **F14.** `service-account role grant|remove` for application roles in
  the account's organization.

### Client

- **F15.** A Go package builds an `http.Client` from a private key and an
  account identifier:
  - it signs assertions;
  - it requests DPoP-bound tokens, using the same key for proofs;
  - it renews a token a minute before expiry;
  - it adds a proof to every API request, and retries once on
    `use_dpop_nonce`.

### Applications

- **F16. Accepting service accounts.** With the new option, `relyingparty`'s
  bearer path accepts a token whose subject has no local principal when the
  token says `principal_type: "service"`. It creates the local principal
  with type `service` and the token's name, then authenticates it with
  memberships from the `orgs` claim. Without the option, the request is
  refused as today.
- **F17. The shared package.** `appauth` exposes the option, and
  `pgstore.PrincipalStore` creates service principals.

### Non-Functional

- **N1.** The grant uses Fosite's RFC 7523 handler. SystemForge supplies
  storage and checks, not protocol code.
- **N2.** Failures return RFC 6749 errors without saying whether a key or
  account exists.
- **N3.** Unit tests cover every refusal. An end-to-end test uses real
  P-256 and RSA keys and ends at an application behind `appauth`.

## Success Criteria

- An operator creates a service account in an organization, grants it a role
  and adds a key with three commands. A Go program with the key file then
  calls an application's API as that account, and the application sees the
  role in the account's memberships.
- A replayed assertion, an expired or revoked key, an assertion for another
  account, a request without a DPoP proof, and a disabled account are each
  refused.
- Removing the account's role makes the application refuse it within one
  token lifetime, or at once with the revocation cache.
- An application that kept API keys for automation can drop them.

## Risks

| Risk | Mitigation |
| --- | --- |
| Long-lived assertions widen the replay window | Required `jti`, a five-minute default maximum, the JTI store |
| Over-broad tokens | Scopes intersected across request, key and account; roles only in one organization |
| A leaked token is used elsewhere | DPoP binding: the token is useless without the private key |
| Key sprawl | Keys carry expiry and last-used time; `key list` shows both |
| Applications create local records for anything claiming to be a service | Only verified SystemAuth tokens are considered, the claim is set by SystemAuth, and the option is off by default |

## Decisions Taken From the Draft

- **The JWT-bearer grant, not client credentials with `private_key_jwt`.**
  With the bearer grant, the token's subject is the service principal, so the
  existing `orgs` claim, memberships, role removal and revocation all work
  unchanged. Client credentials would make the subject the client and need a
  client-to-principal link everywhere. ADR-016's table is updated to match.
- **No client authentication** beyond the assertion. The signed assertion and
  the DPoP proof are the credential.
- **Agents** are out of scope; they use AAuth.

- **The membership role is `service_account`,** the industry's most common
  term for a non-human identity in an organization, so organization pages
  list accounts apart from people. "Service principal" stays the identity
  model's term (`Principal(type=service)`).
- **Operators manage accounts** with commands on the deployment's host in
  this release. Platform administrators and organization owners get an HTTP
  API and console pages as a follow-on.
