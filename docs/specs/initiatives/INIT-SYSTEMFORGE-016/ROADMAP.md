# ROADMAP — Support Requests and Feedback

**Initiative:** `INIT-SYSTEMFORGE-016`
**Repository:** `github.com/plexusone/systemforge`

Every application built on SystemForge can hear its users: a signed-in user
or a visitor sends a support request or feedback, it is stored before
anything is sent, and it reaches the operator's help desk or mailbox, under
the platform's personal-data rules. The decisions are in ADR-019 and the
design in the [TRD](TRD.md). Commits implementing an item carry
`Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — Intake and Delivery

**Theme:** A request sent from an application reaches the operator, and its text does not outlive its use

- [ ] `RMI-SYSTEMFORGE-222` `support` package: `Open` with the SQL store on the platform database, the desk order ending with mail, the `Requesters` port, rate limits, the observer and audit, and `MigrateSchema`
- [ ] `RMI-SYSTEMFORGE-223` `support/turnstile`: a `ChallengeVerifier` over Cloudflare's `siteverify`, with hostname checks and failures that never pass
- [ ] `RMI-SYSTEMFORGE-224` The API: a signed-in request, the requester's own list, and a visitor request with a challenge, with the organization and reply-address rules
  - Depends on: `RMI-SYSTEMFORGE-222`
- [ ] `RMI-SYSTEMFORGE-225` Jobs: delivery, status refresh and clearing, run by every instance
  - Depends on: `RMI-SYSTEMFORGE-222`
- [ ] `RMI-SYSTEMFORGE-226` systemauthsvc: the `support:` configuration, host desks in `Options`, the mail sender kept for the mail desk, `Requesters` over the identity store, migration, mounting and jobs
  - Depends on: `RMI-SYSTEMFORGE-223`, `RMI-SYSTEMFORGE-224`, `RMI-SYSTEMFORGE-225`
- [ ] `RMI-SYSTEMFORGE-227` Guide, configuration reference and release notes
  - Depends on: `RMI-SYSTEMFORGE-226`

## Phase 2 — Operators and Organizations

**Theme:** Operators and organization administrators see what they are allowed to, through the platform

- [ ] `RMI-SYSTEMFORGE-228` Permissions `support.request.read` and `support.desk.configure`, and the `support_agent` platform role
- [ ] `RMI-SYSTEMFORGE-229` Operator API: list and read without cleared text, and redeliver or skip to the next desk
  - Depends on: `RMI-SYSTEMFORGE-228`
- [ ] `RMI-SYSTEMFORGE-230` Organization view: the index for owners and admins, shared text, billing requests, and the sharing policy
- [ ] `RMI-SYSTEMFORGE-231` The `support` command in the CLI and the MCP server, over one API client
  - Depends on: `RMI-SYSTEMFORGE-229`

## Phase 3 — Governance

**Theme:** Support requests are covered by holds, export and erasure like the rest of a user's data

- [ ] `RMI-SYSTEMFORGE-232` Holds (ADR-012) supplied to supportforge, so a held requester's requests are neither cleared nor erased
- [ ] `RMI-SYSTEMFORGE-233` supportforge's classification registered with the data catalog (ADR-011)
- [ ] `RMI-SYSTEMFORGE-234` Export and erasure include support requests and the desk's copy
  - Depends on: `RMI-SYSTEMFORGE-232`, `RMI-SYSTEMFORGE-233`
