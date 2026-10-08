# ADR-006: Organization Lifecycle — Signup, Personal and Team Organizations, Slugs

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-002 (social login creates principals), ADR-004 (the
`Principal` root), ADR-005 (managed principals), ADR-007 (memberships as
claims), ADR-008 (resource-scoped collaborators).

## Context

SystemForge already models organizations with a type (`personal`, `team`,
`enterprise`), a plan, an owner, memberships with roles, invites, and
ownership transfer (`identity/organization`, `identity/invite`). The
`identity/signup` package creates a principal together with a personal
organization. What is missing is the lifecycle around them:

- **Social login does not sign up.** SystemAuth's GitHub and Google login
  (ADR-002) creates a bare principal and never calls `signup`, so a person's
  first sign-in leaves them in no organization. Every application then
  needs an operator step before the person can do anything.
- **Slugs have no rules.** `Update` can change a slug freely; nothing
  remembers a freed slug, so a rename can be followed at once by someone
  else taking the old name, and links to the old slug break.
- **A personal organization cannot become a team.** When a solo user wants
  members, their only path is a new organization and moving everything.
- **Personal organizations do not refuse members.** The type exists but
  nothing enforces what makes it personal.

The model to follow is GitHub's: a person always has a personal account
(here, a personal organization) and belongs to zero or more organizations.
The person's handle is theirs; organizations have their own names in the
same namespace.

## Decision

1. **A first login is a signup.** SystemAuth's social login calls
   `signup.SignupOrGetExisting` for a principal it has not seen: the
   principal and its personal organization are created in one transaction,
   with the principal as owner. A later login resolves to the existing
   principal by provider identity first, then by verified email (ADR-002).
2. **The personal slug comes from how the person arrived:**
   - GitHub login: the GitHub username;
   - Google login: the local part of the email address (before `@`);
   - a managed principal (ADR-005): a name its manager enters, or a
     generated slug that reveals nothing about the person (for example two
     words and a number);
   - on collision, a numeric suffix.
3. **A personal organization has exactly one member: its owner.**
   `AddMember` and invites to a personal organization are refused, except
   for collaborators (ADR-008). `TransferOwnership` of a personal
   organization is refused; it is the person's own.
4. **Personal and team organizations share one slug namespace**, and the
   person always keeps their handle:
   - a personal organization's slug is the person's handle and stays with
     the person;
   - to give a handle to an organization, the person first renames their
     personal organization, then the organization takes the freed slug.
5. **Every slug change frees the old slug into a 7-day cooling-off period**,
   whether a personal or team organization is renamed. During those 7 days
   only the principal that gave the slug up, or an organization that
   principal owns, may take it. After 7 days it is free for anyone. The
   same rule applies in every direction: person to organization,
   organization to person, organization to organization, and a person who
   changes their mind reclaims their handle.
6. **A freed slug resolves to its previous organization as an alias** for
   the cooling-off period, so existing links keep working, until it is
   reassigned or the period ends. Slug lookups consult aliases after exact
   matches.
7. **A personal organization can be converted to a team organization** in
   one transaction:
   - the organization keeps its ID, data, plan and memberships, and its type
     becomes `team`; its owner becomes the team's first owner;
   - it takes a new slug chosen at conversion, which must be free (the
     person can hand over their handle by renaming first, under 5);
   - a new personal organization is created for the person, with their
     handle.
8. **Plans are independent of type, and pricing and packaging are the
   application's.** A personal organization can hold any plan,
   subscription or license a team organization can. SystemForge provides
   pricing and packaging through `marketplace` (listings with tiers,
   subscriptions, licenses with seats, Stripe billing) and does not fix
   the policy:
   - plans move in either direction: free to paid, paid to free, and
     between tiers, with downgrades and cancellations taking effect at the
     period end where the application wants that;
   - packaging is per product or bundle, so an organization may be on a
     free tier of product A and a paid tier of A+B, as with Zoom's
     products;
   - freemium or not, and trials with a configurable length (30 days by
     default) that convert or lapse, are the application's choices,
     expressed as listings and tiers;
   - an organization's entitlements (ADR-007 `apps`) derive from its
     active subscriptions and licenses per listing, not from one
     organization-wide plan. The `plan` column on `sf_organizations` is
     informational and is not consulted for entitlement.

### Schema

- `sf_slug_reservations` (slug, released_by_principal_id,
  released_from_organization_id, released_at, expires_at): one row per
  freed slug, deleted when reassigned or expired. `SlugAvailable` and
  `GetBySlug` read it.
- No change to `sf_organizations`; `org_type` and `slug` already exist.

### API

- `organization.Service` gains `Rename(ctx, orgID, slug)`,
  `ConvertToTeam(ctx, orgID, teamSlug)` and `ResolveSlug(ctx, slug)` (exact
  or alias).
- `signup` gains `SlugForLogin(provider, providerLogin, email)` so SystemAuth
  and other callers derive the personal slug the same way.

## Consequences

- **A new person has a working organization after one login**, with no
  operator involved. Applications that read memberships from SystemAuth
  (ADR-007) can provision themselves for it on first use.
- **Renames are safe and reversible for a week**, and old links keep
  working for that week.
- **Going from solo to team keeps the organization's ID**, so applications
  keyed by organization ID see no change; only the type and slug change.
- **`AddMember` and `TransferOwnership` gain a type check**; existing tests
  that add members to personal organizations must use team organizations.
- **Entitlement is per listing, not per organization.** Applications read
  what an organization may use from its subscriptions and licenses; any
  code that read `Organization.plan` for access decisions must move to
  the marketplace, and the enum stays only as a display or reporting
  value.
- **Slug derivation lives in one place**, so every login provider and the
  managed-principal flow produce the same shape of handle.
