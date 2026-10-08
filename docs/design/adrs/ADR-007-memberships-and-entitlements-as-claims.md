# ADR-007: Organization Memberships and Entitlements as Claims

**Status:** Accepted
**Deciders:** @grokify
**Relates to:** ADR-002 (relying parties federate to SystemAuth), ADR-006
(organization lifecycle), ADR-008 (resource-scoped collaborators),
INIT-SYSTEMFORGE-005 (relying-party contract).
**Updates:** `docs/design/architecture/organizations.md` (memberships, application roles, claims).

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

1. **Access has three layers, and the claims carry the first two.**
   - **Organization role** (`owner`, `admin`, `member`, `collaborator` from
     ADR-008): governs the organization itself, its members, billing and
     settings.
   - **Application role**, per application the organization is entitled
     to: one of the roles the application declares in its
     `authz.AppVocabulary` (the standard ladder is `viewer`, `contributor`,
     `maintainer`, `admin`; an application may declare more). It governs
     what the principal may do inside that application. Where the
     application is seat-licensed, holding an application role consumes a
     seat.
   - **Resource grants** (ADR-008) are the application's to look up; they
     are not claims.

   SystemAuth emits the principal's organizations in the ID token and at
   the userinfo endpoint as an `orgs` claim: a list of objects with `id`,
   `slug`, `name`, `type` (`personal`, `team`, `enterprise`), `role` (the
   organization role) and `apps`, a map from application identifier to the
   principal's application role there. An application absent from `apps`
   is one the principal may not open.
2. **Owners hold `admin` in every entitled application**, implicitly, so
   no application can become unadministrable. **Admins do not:** an admin
   manages the organization (members, invites, application roles,
   settings) and holds only the application roles assigned to them, like a
   member. An admin may assign application roles to themselves; the
   assignment is explicit and audited, which is the point. Members hold
   only the application roles assigned to them. Collaborators hold none;
   their access is by resource grant.
3. **Members and admins get no application access by default.** Adding or
   inviting one requires choosing an application role for at least one
   entitled application; applications left unselected stay closed to that
   person.
   Roles are changed per application without touching the membership, and
   removal from the organization removes every application role and grant.
4. **Custom roles are not supported.** The roles available in an
   application are the ones its vocabulary declares. Organization-defined
   roles (permission bundles) and teams (groups that carry application
   roles) are deferred; if assigning roles one person at a time becomes the
   problem, teams are the first addition.
5. **JWT access tokens carry a compact form**: `orgs` as a list of
   `{id, role, apps}` with `apps` as a map of application identifier to
   role, and no slug or name, to keep the token small. Applications that need slug,
   name or entitlements read them from the ID token, userinfo, or the
   memberships endpoint.
6. **Large membership lists are truncated, not dropped.** A token carries at
   most 50 organizations, ordered personal first, then by most recent
   membership, and sets `orgs_truncated: true` when it omitted any.
   `GET /userinfo/memberships` returns the full, paginated list for the
   presenting token's principal.
7. **The relying-party package reads memberships from claims by default.**
   `relyingparty` gains `ClaimsMemberships` (from the ID token or userinfo)
   and `RemoteMemberships` (from the memberships endpoint, used when
   `orgs_truncated` is set or the compact access-token form is all the
   application has). `LocalMemberships` remains for development and tests
   and is documented as not for production.
8. **Entitlements come from the marketplace.** The applications an
   organization may assign roles in are derived from its active
   subscriptions and licenses, mapped to application identifiers registered
   through `authz.AppVocabulary`. A deployment may declare applications
   every organization is entitled to by default. Application roles are
   stored per (principal, organization, application) in a new
   `sf_app_roles` table, which replaces seat assignments as the record of
   who may use what; a seat-licensed application counts its rows against
   the license.
9. **Freshness is bounded by token lifetime, and removals revoke.** Removing
   a principal from an organization, or changing their role, revokes the
   principal's refresh tokens, so the next refresh carries the new
   memberships; access-token lifetime bounds how long the old ones are
   honored. Applications must handle a membership that disappears between
   requests.
10. **Applications stop keeping membership and role tables.** An
    application keys its data by the SystemAuth organization ID, reads the
    principal's application role from the claims, and provisions itself for
    an organization on first use by a principal holding a role in it; it
    does not store who the members are or what their roles are.

## Consequences

- **One invite carries the person's application roles**, chosen by the
  inviter per application, and one removal takes every role away. Nobody
  gets into an application by being a member alone.
- **Applications need no organization, membership or role tables**, only
  an organization ID on their own records and a mapping from their
  vocabulary roles to permissions.
- **Invitation and member-management screens become role pickers**: the
  entitled applications, each with its ladder, none selected by default.
- **Token size is bounded** by the 50-organization cap; applications with
  users in more organizations than that must use the memberships endpoint.
- **SystemAuth is on the path of every organization decision.** Relying
  parties cache memberships for the token lifetime and must tolerate the
  endpoint being unavailable (serve from the last token).
- **The marketplace becomes the entitlement source**, so an application
  that is free for everyone must still be registered as a default
  entitlement, or every organization is refused.
