# ADR-005: Managed Principals and Manager Relationships

**Status:** Accepted. Amended by ADR-009: management is a relationship, independent of email; the definition of *managed principal* and invariant 4 below are superseded by it.
**Deciders:** @grokify
**Relates to:** ADR-004 / INIT-SYSTEMFORGE-008 (single `Principal` root this
builds on), INIT-SYSTEMFORGE-006 (email verification, used when a managed
principal later attaches an email), INIT-SYSTEMFORGE-001 (base authorization
schema this extends), and INIT-SYSTEMFORGE-007 (the RMIs that execute this).

## Context

Every human in SystemForge is a `Principal(type=human)` + `Human` with a
required, unique email, authenticated by password, social login, or
federation. That is the right default for a SaaS identity platform, and it is
what every current consumer needs.

A new class of consumer needs humans who **cannot** have an email and cannot
hold their own credentials: young children in a learning application, where
a parent or teacher must create the account, issue a way to sign in (a code
rendered as a QR), see what the child did, and be able to revoke or delete.
The same shape recurs outside education: a caregiver managing a dependent's
account, a coach managing an athlete's, an organization provisioning an
account for a person who will claim it later.

The naive answers are bad:

- A placeholder email (`child-<id>@example.invalid`) satisfies the schema and
  poisons everything downstream: verification mail, SCIM exports, audit
  logs, "forgot password," and any future deliverability feature.
- An application-local child table outside SystemForge leaves the child with
  no platform identity: no shared mastery record across applications, no
  SystemAuth session, and a parallel authorization model.
- Making email optional for *everyone* would let any application create
  unaddressable accounts by accident, which no current consumer wants and
  which complicates recovery and compliance for the common case.

Two facts about the existing model make a cleaner answer possible. First,
`principal.Capabilities` already expresses per-principal limits
(`CanManageProfile`, `CanDelegate`, ...). Second, `sf_credentials` already
models typed, expiring, revocable credentials owned by a principal, so a
manager-issued sign-in code is a new credential *type*, not a new subsystem.

## Decision

**Email stays required by default.** A human without an email is a
**managed principal**: an explicitly opted-in state that requires at least
one **manager** who does have an email. SystemForge provides the primitive;
applications supply the meaning.

### Vocabulary

SystemForge does not know *parent*, *child*, *teacher*, or *student*. It
knows:

- **Managed principal:** a `Principal(type=human)` whose `Human.email` is
  null. It cannot manage its own profile or credentials
  (`CanManageProfile = false`, `CanDelegate = false`).
- **Manager relationship:** a directed edge from a manager principal to a
  managed principal, with a **role**. Two roles are built in because two
  consumers already need both:
  - **`guardian`**: full control. Consent, deletion, billing, credential
    issuance and revocation, adding or removing other managers.
  - **`educator`**: operational control. Credential issuance and revocation,
    profile read, adding a `guardian` by claim. No deletion, billing, or
    consent authority.

  Applications may register further roles through the authorization
  vocabulary; the two built-ins are the platform contract.

### Invariants (enforced by SystemForge, transactionally)

1. A managed principal has **at least one active manager** at all times.
   Creating one without a manager, or removing its last manager, is refused;
   the account must be deactivated or deleted instead.
2. A manager is a `Principal(type=human)` that is **active and has an
   email**. Managed principals cannot manage other principals.
3. Managed principals exist only when **both** the SystemAuth deployment
   (`managed_principals.enabled`, default `false`) **and** the requesting
   OAuth client (`managed_principals_enabled`, default `false`) allow them.
   The client is the `OAuthApp` SystemAuth authenticates; the `Application`
   principal extension is unrelated. Every other application behaves exactly as today.
4. A managed principal may **later attach an email** (verified per
   INIT-SYSTEMFORGE-006), after which it is an ordinary human; manager
   relationships may remain, and only then may the last one be removed.

### Sign-in

A new credential type **`login_token`**: a high-entropy opaque secret issued
by a manager for a managed principal, stored hashed, with an expiry and
revocation like every other `sf_credentials` row. Applications render it as a
QR code, a printed card, or a link; SystemForge never cares which. It is
reusable by default (a child scans the same code each day) and may be marked
single-use. The platform default lifetime is **30 days**, the posture of a
general SaaS identity platform; an opted-in application may set its own
default (classroom products conventionally issue codes for a term or school
year) under a platform ceiling, and single-use tokens are short-lived (20
minutes) like the backup codes such products offer. SystemAuth exchanges a
token for a session whose claims mark the subject as managed; managers can
list and revoke a managed principal's tokens and active sessions.

Deletion of a managed principal is a `guardian` or platform-administrator
action only. An `educator` cannot delete one, even one that never received a
`guardian`; orphan cleanup is an administrative task. This starts strict on
purpose and is revisited only on evidence.

### Identifier

`Principal.identifier` is the email when one exists; otherwise a generated
handle (`human:<principal-id>`). It is a lookup key, not an address, and is
documented as such. Attaching an email updates it.

### Authorization

The base SpiceDB schema gains `guardian` and `educator` relations on
`principal`, with platform permissions (`manage_account`,
`manage_credentials`, `view_profile`). Applications add domain permissions
(progress, certificates, play limits) through their own facets, as the
cross-Forge conventions already prescribe.

## Consequences

- No current consumer changes behavior: with both flags off, a human without
  an email cannot be created, and the only visible change is that
  `HumanPrincipal.Email` is now optional in Go types and claims.
- Every code path that assumed an email exists is audited and made
  conditional: social-login linking by verified email, invitations (which
  target an email and therefore never produce managed principals; managers
  add them directly), signup, SCIM (`userName` becomes the identifier;
  `emails` is omitted when absent), OIDC `userinfo` and ID-token `email`
  claims, relying-party principal views, and marketplace purchasing (managed
  principals cannot purchase; billing is a `guardian` action).
- Consent records, age handling, and regulatory obligations (COPPA, FERPA,
  and their non-US equivalents) remain **application concerns**. SystemForge
  gives the application a manager with the authority to consent and delete;
  it does not record the consent itself.
- A reusable `login_token` is password-equivalent for the managed principal.
  The mitigations are structural: managed sessions carry reduced
  capabilities, the exchange endpoint is rate-limited and reveals nothing on
  failure, tokens expire, and managers see and can revoke every token and
  session. Applications that need stronger assurance can request single-use
  tokens or add device binding.
- `Account` was deliberately **not** used anywhere in this vocabulary: in a
  multi-tenant platform with marketplace billing it reads as the tenant or
  the paying relationship, not the person.
- Released in v0.14.0 together with INIT-SYSTEMFORGE-008, rather than as
  a separate v0.15.0: nothing was released between them, and the local
  `auth-go` replace directive left no earlier commit that could be tagged.
  The Go-level change to `Email` is noted in the release notes.

## References

- INIT-SYSTEMFORGE-007 ROADMAP (execution RMIs).
- ADR-004 (single identity root), ADR-003 (verified email), and
  `docs/authz-conventions.md` (facet model the authorization change follows).
- Affected surfaces: `identity/ent/schema/{human,application,credential}.go`,
  a new `identity/managedprincipal` package, `identity/credential`,
  `identity/systemauth` (login-token exchange, claims, userinfo),
  `identity/{invite,signup,scim,relyingparty}`, `authz/spicedb_base.go`,
  `marketplace` (purchaser checks), `docs/identity/*`.
