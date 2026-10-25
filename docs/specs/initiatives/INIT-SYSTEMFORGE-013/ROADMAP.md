# ROADMAP — Invite-Gated Sign-Up

**Initiative:** `INIT-SYSTEMFORGE-013`
**Repository:** `github.com/plexusone/systemforge`

Invite codes, member invites with allowances, attribution, an HTTP API, and
admin and member pages, on top of invite-only sign-up. Commits implementing
an item carry `Refs: RMI-SYSTEMFORGE-<NNN>` or `Refs: RMI-SYSTEMFORGEWEB-<NNN>`.

## Phase 1 — Invite Codes

**Theme:** A code with a use limit admits exactly that many accounts

- [ ] `RMI-SYSTEMFORGE-178` Schema: `sf_signup_codes`, `sf_signup_code_redemptions`, `sf_signup_allowances`, invite and waitlist attribution columns with migration `0011`, and the new tables in `RestrictedSharedTables`
- [ ] `RMI-SYSTEMFORGE-179` `signupgate.CodeStore`: code format and normalization, hash-only storage, atomic reserve, release, redeem, and redemptions; the gate admits an email invite or a code, and `SignupGateAborter` releases a reservation when account creation fails
  - Depends on: `RMI-SYSTEMFORGE-178`
- [ ] `RMI-SYSTEMFORGE-180` Carrying a code through sign-in: the `__Host-sf_signup_code` cookie, `invite_code` on `/login/{provider}`, `WithSignupCode` on the context, and the rate-limited `/signup?code=` page
  - Depends on: `RMI-SYSTEMFORGE-179`
- [ ] `RMI-SYSTEMFORGE-181` Commands: `code create|list|revoke`, `waitlist invite`, and `admin grant|revoke|list` for platform admins, registered in `cmd/systemauth`
  - Depends on: `RMI-SYSTEMFORGE-179`

## Phase 2 — Member Invites and the API

**Theme:** Operators and members manage invites over HTTP

- [ ] `RMI-SYSTEMFORGE-182` Member allowances: default and per-member allowances, held-count rule, `CreateMemberCode` under a row lock, and member revoke; the `allowance` command
  - Depends on: `RMI-SYSTEMFORGE-179`
- [ ] `RMI-SYSTEMFORGE-183` `signupgate/signupapi`: operator and member routes, session and platform-admin hooks, origin checks, no-store responses, and audit events
  - Depends on: `RMI-SYSTEMFORGE-182`
- [ ] `RMI-SYSTEMFORGE-184` systemauthsvc wiring: `SignupCodes`, `MemberInvites`, `SignupPage`, and `SignupAPI` options; `Service.SignupCodes()` and `Service.SignupAPI()`; an end-to-end test from code to account
  - Depends on: `RMI-SYSTEMFORGE-180`
  - Depends on: `RMI-SYSTEMFORGE-183`
- [ ] `RMI-SYSTEMFORGE-185` Documentation: an invite-gated sign-up guide, deployment options and commands, and the changelog
  - Depends on: `RMI-SYSTEMFORGE-184`

## Phase 3 — Pages

**Theme:** Operators and members use invites without a terminal

- [ ] `RMI-SYSTEMFORGEWEB-027` `@plexusone/invites` package: typed API client, wire types, `ApiError`, and `useLoad`
  - Depends on: `RMI-SYSTEMFORGE-183`
- [ ] `RMI-SYSTEMFORGEWEB-028` `InviteAdminPage`: codes, email invites, waitlist, allowances, and joined accounts, with show-once links and inline revoke
  - Depends on: `RMI-SYSTEMFORGEWEB-027`
- [ ] `RMI-SYSTEMFORGEWEB-029` `InvitePeoplePage`: the member's allowance, create and copy an invite link, and revoke unused ones
  - Depends on: `RMI-SYSTEMFORGEWEB-027`
- [ ] `RMI-SYSTEMFORGEWEB-030` Package docs, changelog, and release
  - Depends on: `RMI-SYSTEMFORGEWEB-028`
  - Depends on: `RMI-SYSTEMFORGEWEB-029`
