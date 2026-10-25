# PLAN — Invite-Gated Sign-Up

**Initiative:** `INIT-SYSTEMFORGE-013`

## Entry Gate

- Invite-only sign-up, the waitlist, and the sign-up age question are
  released and documented.
- The design in the TRD is accepted: codes stored as hashes and shown once,
  reservation in `AllowSignup` with `SignupGateAborter` to undo it, the code
  carried by cookie and context, and the API as a handler the host mounts.

## Build Order

### Phase 1 — Invite Codes

Schema first, because every later item reads it. The store and gate come
next so a code works from the command line before any page exists.

1. Schema, migration file, and restricted tables.
2. `CodeStore` with format, reserve, release, and redeem; the code-aware gate
   and `SignupGateAborter`.
3. Carrying the code: cookie, `invite_code`, and the `/signup` page.
4. Commands: `code`, `waitlist invite`, `admin`.

### Phase 2 — Member Invites and the API

5. Allowances and member codes.
6. `signupapi` with audit events.
7. systemauthsvc options and accessors; `allowance` command.
8. Documentation: a sign-up guide, deployment flags, changelog.

### Phase 3 — Pages

9. `@plexusone/invites`: API client and types.
10. `InviteAdminPage`.
11. `InvitePeoplePage`.
12. Package docs and release.

## Release

Phases 1 and 2 ship together in the next systemforge minor release, after the
release in progress. Phase 3 ships as a systemforge-web release that needs
it. A new npm package goes through npm's staging approval on first publish.

## Decisions

- **Codes are stored as hashes and shown once.** A database read never yields
  a working code, which matches organization invite tokens. A member who loses
  a link revokes it and creates another; the slot comes back.
- **Reserve, then redeem.** Reserving in `AllowSignup` with a conditional
  update keeps use limits exact under concurrency without a transaction
  spanning account creation. The cost is a use lost if the process stops
  between the two, which only ever admits fewer people.
- **An email invite wins over a code.** A person both invited by address and
  holding a code does not use up the code.
- **The API is a handler, not a SystemAuth route only.** A host that embeds
  SystemAuth and runs its own session (as with `console`) mounts the same
  handler behind it, so its pages stay same-origin.
- **snake_case JSON**, matching every other SystemAuth API, not camelCase.
- **The pages are components, not an `AppModule`.** Host routing is
  organization-scoped; admin and invite pages are not.

## Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| A leaked operator code admits strangers | Use limits, expiry, labels, and revoke; redemptions show who used it |
| Guessing codes through `/signup` | 80-bit codes, rate limit per client address, no difference between unknown, expired, and used-up |
| Members hand invites to people the product is not ready for | Allowances default to 0; operators raise them per member |
| A reservation leaks on a crash | Only reduces admissions; `use_count` versus redemptions shows it |
| Ungated account paths (SCIM, federation, managed principals) | Unchanged and documented, as today |

## Follow-On

- Email delivery of invites once verified email (INIT-SYSTEMFORGE-006) lands.
- Waitlist confirmation emails and a "notify when invited" flow.
- Per-label reports: sign-ups and activity by cohort.
