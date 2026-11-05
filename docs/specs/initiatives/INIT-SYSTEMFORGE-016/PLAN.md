# PLAN — Support Requests and Feedback

**Initiative:** `INIT-SYSTEMFORGE-016`

## Approach

Ship the smallest path that gets a request from an application to the
operator: intake, delivery and clearing (Phase 1). It is enough for a
deployment to launch with a contact form and a help desk. Operator tools, the
organization view and governance follow in their own releases.

supportforge does the work. This package supplies the platform's pieces:
the session, verified email, memberships, rate limits, audit, mail and the
jobs. It holds no support logic of its own.

## Phases

1. **Intake and delivery.** The package, the Turnstile verifier, the API, the
   jobs, then the systemauthsvc wiring, then the docs and release notes.
2. **Operators and organizations.** Permissions and the role first, then the
   operator API and the organization view, then the CLI and MCP server.
3. **Governance.** Holds and catalog registration, then export and erasure.

## Steps

1. **`support.Open` and `MigrateSchema`.** Options, validation, the desk
   order with mail last, and the ports. Tested with the in-memory store.
2. **`support/turnstile`.** Independent of the rest; tested against
   `httptest`.
3. **The handler.** The three routes, the organization and reply-address
   rules, and the error mapping.
4. **`RunJobs`.** The three loops, tested with a short interval and a
   canceled context.
5. **systemauthsvc.** The `support:` section and its validation, keeping the
   mail sender, `Requesters` over `Human` and memberships, migration, mounting
   on the router and in the console, and the jobs.
6. **Docs.** A guide for enabling support and adding a desk, the
   configuration reference, and release notes.

## Dependencies

- A tagged release of `github.com/plexusone/supportforge` with the SQL store
  and the clear job.
- A deployment that enables support needs outbound mail configured.

## Risks

- **No outbound mail.** A deployment without a mail sender cannot enable
  support. `New` reports it, so it is found at startup, not when the first
  request is lost.
- **Tokens without the support scopes.** A product client must be allowed
  `systemforge:support:write` and `:read`. The guide says so, and the
  handler answers a missing scope with the usual bearer error.
