# PLAN — Support Requests and Feedback

**Initiative:** `INIT-SYSTEMFORGE-016`

## Approach

Ship the smallest path that gets a request from an application to the
operator: intake, delivery, clearing and the form (Phase 1). It is enough for
a deployment to launch with a contact form and a help desk or a mailbox.
Operator tools, the organization view, governance and replies follow in their
own releases.

supportforge does the work. This package supplies the platform's pieces:
the session, verified email, memberships, rate limits, audit, mail and the
jobs. It holds no support logic of its own, and no vendor integrations: a
host supplies its help desks and its bot challenge through supportforge's
interfaces.

## Phases

1. **Intake and delivery.** The package, the API, the jobs, then the
   systemauthsvc wiring and the web package, then the docs and release notes.
2. **Outbound mail.** The mail cap, then failing cleanly when the provider
   blocks sending. Needed only by deployments that send mail.
3. **Operators and organizations.** Permissions and the role first, then the
   operator API and the organization view, then the CLI and MCP server.
4. **Governance.** Holds and catalog registration, then export and erasure.
5. **Replies.** Drafts first, then approval and sending.

## Steps

1. **`support.Open` and `MigrateSchema`.** Options, validation, the desk
   order with the mail desk last and optional, and the ports. Tested with
   the in-memory store and desk.
2. **The handler.** The three routes, the visitor route only with a
   challenge, the organization and reply-address rules, and the error
   mapping.
3. **`RunJobs`.** The three loops, tested with a short interval and a
   canceled context.
4. **systemauthsvc.** The `support:` section and its validation, the host's
   desks and challenge in `Options`, keeping the mail sender, `Requesters`
   over `Human` and memberships, migration, mounting on the router and in the
   console, and the jobs.
5. **`@plexusone/support`.** The button, the panel and "My requests" in
   systemforge-web, over the API.
6. **Docs.** A guide for enabling support and adding a desk or a challenge,
   the configuration reference, and release notes.
7. **The mail cap** (Phase 2). The omnimail decorator and its `Counter` port
   first, then the database counter, then the admin API. Tested at each limit,
   with a counter that fails, and across two instances on one database.

## Dependencies

- A tagged release of `github.com/plexusone/supportforge` with the SQL store
  and the clear job.
- A deployment that enables support needs at least one desk: its own, the
  mail desk, or both. A deployment that accepts visitors supplies a
  `ChallengeVerifier`.
- For Phase 2 only:
  - An omnimail release with the capped sender, its `Counter` port,
    `ErrLimitReached`, and `ErrSendingBlocked`, which a sender returns when
    the provider denies sending or has turned it off.
  - supportforge's mail desk treating `ErrLimitReached` and
    `ErrSendingBlocked` as retryable, and recording a skipped acknowledgment
    rather than failing the delivery.

## Risks

- **No desk accepts a request.** Without mail there is no last-resort desk,
  so a request waits in the outbox while every desk refuses it. The observer
  reports it and the deployment alerts on requests waiting too long.
- **Mail stops at the cap.** Sign-in verification stops too when the
  monthly or daily limit is reached. Per-kind limits keep acknowledgments from
  using it up, alerts come before the limit, and an administrator can raise
  it without a deploy.
- **Tokens without the support scopes.** A product client must be allowed
  `systemforge:support:write` and `:read`. The guide says so, and the
  handler answers a missing scope with the usual bearer error.
