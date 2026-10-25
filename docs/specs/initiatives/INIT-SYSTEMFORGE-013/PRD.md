# PRD — Invite-Gated Sign-Up

**Initiative:** `INIT-SYSTEMFORGE-013`
**Status:** Draft
**Home repo:** `github.com/plexusone/systemforge`
**Builds on:** invite-only sign-up (`identity/signupgate`, `--invite-only`)

## Problem

A product launching to a small audience wants to grow on purpose: first the
people its operators know by name, then people those early members vouch for,
then larger cohorts. SystemAuth's invite-only mode covers only the first step.

- **An invite is an email address.** Operators must know each address in
  advance. There is no way to hand a link to a community, an event, or a
  partner and cap how many people it admits.
- **Members cannot invite anyone.** Growth through the people already inside,
  with a limit per member, is not possible.
- **Nobody knows who brought whom.** `invited_by` is a free-text operator
  label, so a deployment cannot tell which cohort or member an account came
  from.
- **Everything is a command on the server host.** Invites and the waitlist
  are managed by `systemauth invite` and `systemauth waitlist` with database
  access. There is no API, so no admin page, and no way for a member to see
  or share their own invites.
- **The waitlist is a dead end.** An operator exports it as CSV and invites
  addresses by hand; nothing records which entries were invited.
- **There is no way to create the first platform admin** without editing the
  database.

## Goals

1. **Invite codes.** An operator creates a code with a use limit, an optional
   expiry, and a label naming the cohort. Anyone holding it can sign up while
   it has uses left. A code is shared as a link.
2. **Member invites.** An operator gives a member an allowance of invites, or
   gives every member a default allowance. A member creates single-use codes
   up to their allowance and shares them.
3. **Attribution.** Every account created through an invite or a code records
   which invite or code admitted it, and who created that invite or code.
4. **An HTTP API** for operators (allowlist, codes, waitlist, allowances,
   attribution) and for members (their own allowance and codes), mountable on
   SystemAuth or inside a host application that embeds it.
5. **Pages** in systemforge-web: an operator page and a member "Invite people"
   page, built on the API.
6. **Waitlist to invite in one step**, recording when each entry was invited.
7. **A platform admin command** to grant, revoke, and list platform admins.
8. **Unchanged guarantees.** A verified email is still required. People who
   already have an account sign in as before. A refusal still does not say
   why.

## Non-Goals

- **Sending email.** Invites are shared by the operator or the member. Email
  delivery can follow once verified email (INIT-SYSTEMFORGE-006) lands.
- **Gating other account-creation paths.** SCIM, federation sync, managed
  principals, and `signup.Service` stay ungated, as they are today.
- **Organization invites** (`identity/invite`). Those add an existing or new
  person to an organization; this initiative decides who may create an
  account at all.
- **Referral rewards** or any incentive tied to invites.

## Users

| User | Needs |
| --- | --- |
| **Operator** (platform admin) | Invite named addresses, create cohort codes, invite from the waitlist, set member allowances, see who joined through what |
| **Member** | See how many invites they have, create a code, copy its link, revoke one they no longer want used |
| **Invited person** | Follow a link, sign in with a provider, land in the product |
| **Host application** | Turn the feature on with options, mount the API behind its own session or SystemAuth's, drop in the pages |

## Requirements

### Invite codes

- A code is random, at least 60 bits, typed in groups of four characters from
  an unambiguous alphabet, and stored only as a hash. It is shown once, when
  created.
- A code has a use limit (at least 1), an optional expiry, a label, and an
  optional note. An operator can revoke it at any time.
- A code is redeemed only when an account is created. Signing in to an
  existing account never uses a code.
- Use limits hold under concurrent sign-ups: a code with N uses admits at most
  N accounts.
- A code can be entered on a sign-up page or carried in a link.

### Member invites

- A member's allowance is a number set by an operator, or the deployment's
  default when none is set. The default is 0.
- A member may hold codes up to their allowance, counting codes already used
  and codes still pending. Revoking or letting a pending code expire returns
  its slot.
- Member codes are single-use and expire after a deployment-set period
  (default 14 days).
- A member sees only their own codes.

### Allowlist and waitlist

- Email invites work as today, and also record the principal who created them
  when created through the API.
- Inviting from the waitlist creates email invites for the chosen entries and
  marks them invited, without removing them.

### Attribution

- Each account admitted by a code has a redemption record: the code, the new
  principal, the email, and when. Email invites keep their redeemed-by fields.
- Operators can list accounts by code, by inviting member, and by label.

### Access

- Operator endpoints require a platform admin. Member endpoints require a
  signed-in person. Both are same-origin, state-changing requests are checked
  for origin, and responses are not cached.
- Every operator and member change is audit-logged when the host provides an
  audit emitter.

## Success Criteria

1. An operator creates a code for 20 people from the admin page, and the
   twenty-first sign-up with it is refused, including under concurrent
   sign-ups in tests.
2. A member with an allowance of 3 creates three codes from the "Invite
   people" page, cannot create a fourth, and gets a slot back by revoking an
   unused one.
3. The admin page shows each account's code or invite and inviter.
4. A host application enables all of this with options and two pages, with no
   database access of its own.
5. The first platform admin is created with one command.
