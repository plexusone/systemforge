# ROADMAP — Support Requests and Feedback

**Initiative:** `INIT-SYSTEMFORGE-016`
**Repository:** `github.com/plexusone/systemforge`

Every application built on SystemForge can hear its users: a signed-in user
or a visitor sends a support request or feedback, it is stored before
anything is sent, and it reaches the operator's help desk or mailbox, under
the platform's personal-data rules. SystemForge supplies the interfaces and
the mail desk; a host composes its own help desks and bot challenge. The
decisions are in
[ADR-019](../../../design/adrs/ADR-019-support-requests-and-feedback.md) and
the design in the [TRD](TRD.md). Commits implementing an item carry
`Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — Intake and Delivery

**Theme:** A request sent from an application reaches the operator, and its text does not outlive its use

- [ ] `RMI-SYSTEMFORGE-251` `support` package: `Open` with the SQL store on the platform database, the host's desks with the mail desk last when mail is configured, the `Requesters` and challenge ports, rate limits, the observer and audit, and `MigrateSchema`
- [ ] `RMI-SYSTEMFORGE-252` The API: a signed-in request, the requester's own list, and a visitor request when the host supplies a challenge, with the organization and reply-address rules
  - Depends on: `RMI-SYSTEMFORGE-251`
- [ ] `RMI-SYSTEMFORGE-253` Jobs: delivery, status refresh and clearing, run by every instance
  - Depends on: `RMI-SYSTEMFORGE-251`
- [ ] `RMI-SYSTEMFORGE-254` systemauthsvc: the `support:` configuration, the host's desks and challenge in `Options`, the mail sender kept for the mail desk, `Requesters` over the identity store, migration, mounting and jobs
  - Depends on: `RMI-SYSTEMFORGE-252`, `RMI-SYSTEMFORGE-253`
- [ ] `RMI-SYSTEMFORGE-255` `@plexusone/support` (systemforge-web): the support button and panel with "Contact support" and "Send feedback", and "My requests"
  - Depends on: `RMI-SYSTEMFORGE-252`
- [ ] `RMI-SYSTEMFORGE-256` Guide, configuration reference and release notes
  - Depends on: `RMI-SYSTEMFORGE-254`, `RMI-SYSTEMFORGE-255`

## Phase 2 — Outbound Mail

**Theme:** A deployment that sends mail cannot be made to send more than its limits, and keeps working when its provider stops sending

- [ ] `RMI-SYSTEMFORGE-257` Mail cap: an omnimail capped sender over a counter on the platform database, monthly, daily, per-recipient and per-kind limits that fail closed, the admin usage and limits API with `mail.limits.read` and `mail.limits.configure`, and alerts
- [ ] `RMI-SYSTEMFORGE-258` Blocked sending: `ErrSendingBlocked` from an omnimail sender handled like a reached limit, by support and address verification

## Phase 3 — Operators and Organizations

**Theme:** Operators and organization administrators see what they are allowed to, through the platform

- [ ] `RMI-SYSTEMFORGE-259` Permissions `support.request.read` and `support.desk.configure`, and the `support_agent` platform role
- [ ] `RMI-SYSTEMFORGE-260` Operator API: list and read without cleared text, and redeliver or skip to the next desk
  - Depends on: `RMI-SYSTEMFORGE-259`
- [ ] `RMI-SYSTEMFORGE-261` Organization view: the index for owners and admins, shared text, billing requests and the sharing policy, in the API and the organization console
- [ ] `RMI-SYSTEMFORGE-262` The `support` command in the CLI and the MCP server, over one API client
  - Depends on: `RMI-SYSTEMFORGE-260`

## Phase 4 — Governance

**Theme:** Support requests are covered by holds, export and erasure like the rest of a user's data

- [ ] `RMI-SYSTEMFORGE-263` Holds (ADR-012) supplied to supportforge, so a held requester's requests are neither cleared nor erased
- [ ] `RMI-SYSTEMFORGE-264` supportforge's classification registered with the data catalog (ADR-011)
- [ ] `RMI-SYSTEMFORGE-265` Export and erasure include support requests and the desk's copy
  - Depends on: `RMI-SYSTEMFORGE-263`, `RMI-SYSTEMFORGE-264`

## Phase 5 — Replies

**Theme:** An agent drafts a reply, and only a person sends it (ADR-019 decision 13)

- [ ] `RMI-SYSTEMFORGE-266` Draft replies: `support.reply.draft`, drafts stored as personal data and cleared once sent or discarded, in the API, the CLI and the MCP server
  - Depends on: `RMI-SYSTEMFORGE-260`
- [ ] `RMI-SYSTEMFORGE-267` Approval and sending: `support.reply.approve`, never held by an agent's grant, a new approval after an edit, sending through the desk, and the audit trail
  - Depends on: `RMI-SYSTEMFORGE-266`

## Out of scope

- Customer-authorized access to a customer's application data (ADR-020), which support requests ask for but which is its own initiative.
- Help-desk adapters and bot challenges. They implement supportforge-core's `Desk` and supportforge's `ChallengeVerifier`, and a host supplies them.
