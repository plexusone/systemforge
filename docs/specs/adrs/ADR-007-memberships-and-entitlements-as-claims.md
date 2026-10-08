# ADR-007: Organization Memberships and Entitlements as Claims

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-002 (relying parties federate to SystemAuth), ADR-006
(organization lifecycle), ADR-008 (resource-scoped collaborators),
INIT-SYSTEMFORGE-005 (relying-party contract).

## Context

SystemForge intends SystemAuth to be the source of truth for organization
memberships, roles and entitlements. The relying-party package says so
(`identity/relyingparty/memberships.go`): a `MembershipSource` may read them
from claims, "until SystemAuth emits them, the default source reads an
app-local table".

SystemAuth does not emit them yet, so every application keeps its own
membership table, fed by operators or by its own invite flow. In a
deployment of several applications behind one SystemAuth, the same
organization has to be created in each application, and a person has to be
added to each, separately. Removing someone from an organization in one
application does not remove them from another.

The marketplace already records what an organization is entitled to
(subscriptions, licenses, seats), and `authz.FeatureAuthorizer` can answer
feature questions, but applications cannot learn an organization's
entitlements from a login either.

## Decision

1. **SystemAuth emits the principal's organizations in the ID token and at
   the userinfo endpoint**, as an `orgs` claim: a list of objects with
   `id`, `slug`, `name`, `type` (`personal`, `team`, `enterprise`), `role`
   (the membership role, including `collaborator` from ADR-008) and `apps`
   (the application identifiers the organization is entitled to and the
   principal holds a seat for, where the application uses seats).
2. **JWT access tokens carry a compact form**: `orgs` as a list of
   `{id, role}` only, to keep the token small. Applications that need slug,
   name or entitlements read them from the ID token, userinfo, or the
   memberships endpoint.
3. **Large membership lists are truncated, not dropped.** A token carries at
   most 50 organizations, ordered personal first, then by most recent
   membership, and sets `orgs_truncated: true` when it omitted any.
   `GET /userinfo/memberships` returns the full, paginated list for the
   presenting token's principal.
4. **The relying-party package reads memberships from claims by default.**
   `relyingparty` gains `ClaimsMemberships` (from the ID token or userinfo)
   and `RemoteMemberships` (from the memberships endpoint, used when
   `orgs_truncated` is set or the compact access-token form is all the
   application has). `LocalMemberships` remains for development and tests
   and is documented as not for production.
5. **Entitlements come from the marketplace.** An organization's `apps` are
   derived from its active subscriptions and licenses, mapped to application
   identifiers registered through `authz.AppVocabulary`. A deployment may
   declare applications every organization is entitled to by default.
6. **Freshness is bounded by token lifetime, and removals revoke.** Removing
   a principal from an organization, or changing their role, revokes the
   principal's refresh tokens, so the next refresh carries the new
   memberships; access-token lifetime bounds how long the old ones are
   honored. Applications must handle a membership that disappears between
   requests.
7. **Applications stop keeping membership tables.** An application keys its
   data by the SystemAuth organization ID and provisions itself for an
   organization on first use by an entitled member; it does not store who
   the members are.

## Consequences

- **One invite gives access to every application** the organization is
  entitled to, and one removal takes it away everywhere.
- **Applications need no organization or membership tables**, only an
  organization ID on their own records.
- **Token size is bounded** by the 50-organization cap; applications with
  users in more organizations than that must use the memberships endpoint.
- **SystemAuth is on the path of every organization decision.** Relying
  parties cache memberships for the token lifetime and must tolerate the
  endpoint being unavailable (serve from the last token).
- **The marketplace becomes the entitlement source**, so an application
  that is free for everyone must still be registered as a default
  entitlement, or every organization is refused.
