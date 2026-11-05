# TRD — Support Requests and Feedback

**Initiative:** `INIT-SYSTEMFORGE-016`

The decisions are in ADR-019. This document says how the first release
builds them: intake, delivery and clearing. Agent tools, the organization
view, replies, holds and catalog registration come in later phases.

## Package

`support` composes [supportforge](https://github.com/plexusone/supportforge)
with the platform, as `connections` does for connectforge. It depends on
`supportforge`, `supportforge/store/sqlstore`, `supportforge/maildesk` and
`supportforge-core`, and nothing in supportforge depends on SystemForge.

```text
support.Open(Options)
  ├── sqlstore.Store            (supportforge_* tables on the platform database)
  ├── supportforge.Service      (intake, outbox, worker, status, clearing)
  │     ├── Desks               host desks first, then the mail desk
  │     ├── ChallengeVerifier   support/turnstile, for visitors
  │     ├── RateLimiter         session/ratelimit storage
  │     └── Observer            the host's hook, plus audit
  ├── Handler(auth, writeAuthErr, logger)
  └── RunJobs(ctx)
```

### Options

```go
type Options struct {
	DB      *sql.DB          // the platform database; required
	Dialect sqlstore.Dialect // required

	// Desks are tried in order before the mail desk, which is always last.
	Desks []supportcore.Desk
	Mail  MailDesk // the support inbox and the sender; required

	Requesters Requesters        // resolves a principal's verified email and memberships; required
	Challenge  supportforge.ChallengeVerifier // required to accept visitors
	Rates      ratelimit.Storage // optional; without it requests are not limited
	Observer   supportforge.Observer // optional
	Audit      audit.Emitter         // optional; without it events go to Logger
	Templates  *supportforge.Templates

	ClearDelay time.Duration // default 7 days
	MaxHold    time.Duration // default 90 days
	Logger     *slog.Logger
}
```

`Requesters` is a port so the package does not reach into the identity Ent
client. systemauthsvc implements it over `Human` (email, `email_verified`)
and organization membership.

### Migration

`MigrateSchema(ctx, db, dialect)` runs `sqlstore.Migrate`. systemauthsvc's
`Migrate` calls it after its own schema and connections, on the same owner
connection. The tables are not merged into SystemForge's Ent client.

## API

Mounted on the SystemAuth router, and again under the console with the
session, as connections are. JSON fields are camelCase; errors are
`{"error": "..."}`.

| Method and path | Who | Scope |
| --- | --- | --- |
| `POST /api/v1/support/requests` | signed in | `systemforge:support:write` |
| `GET /api/v1/support/requests/mine` | signed in | `systemforge:support:read` |
| `POST /api/v1/public/support/requests` | visitor | none; challenge required |

**A signed-in request.**

- The requester comes from the token and `Requesters`, never from the body:
  the principal, the verified email as the reply address, and the
  organization.
- The body may name an organization, which must be one the principal belongs
  to. Without one, a principal in exactly one organization gets it, and
  otherwise the request has none.
- A principal without a verified email may still send feedback with no
  reply wanted. A request wanting a reply is refused with 422.

**A visitor request** carries the reply address and a Turnstile token. It
is rate limited by client address, from `server.ClientAddress()`, and by
address. Its acknowledgment never repeats its text (supportforge).

```json
{
  "product": "vision",
  "kind": "problem",
  "title": "Export fails",
  "body": "It times out after a minute.",
  "page": "/projects/42/export",
  "replyWanted": true,
  "share": false,
  "organizationId": "…"
}
```

`201` answers `{"reference": "SR-…", "shared": false, "shareReason": ""}`.
The response promises an email reply and gives no time.

| supportforge error | Status |
| --- | --- |
| `ErrInvalid` | 400, with the field |
| `ErrChallenge` | 403 |
| `ErrRateLimited` | 429 |
| `ErrNotFound` | 404 |
| anything else | 500, logged without text |

Bodies are read with `MaxBytesReader` and unknown fields are refused. The
public route accepts requests from the deployment's trusted origins only.

## Turnstile

`support/turnstile` verifies a token against Cloudflare's `siteverify`
endpoint with the secret key, the remote address and the expected hostname.
A network failure is an error, never a pass. It has `httptest` tests and no
live calls.

## Jobs

`RunJobs` runs three loops until its context ends:

| Job | Interval | Calls |
| --- | --- | --- |
| Delivery | 15 seconds | `Service.Run` |
| Status | 10 minutes | `Service.RefreshStatuses` |
| Clearing | hourly, and once at start | `Service.Clear` |

Every instance runs them: delivery claims with row locks, and the status and
clearing passes are safe to repeat. systemauthsvc appends `RunJobs` to its
own jobs. Errors and clear reports are logged without text.

## systemauthsvc

A `support:` section in the SystemAuth configuration enables it:

```yaml
support:
  inbox: support@example.com     # where the mail desk sends requests
  from: support@example.com      # the sender of acknowledgments
  turnstile_secret: ${SUPPORT_TURNSTILE_SECRET}
  turnstile_hostnames: [example.com]
  clear_delay: 168h
  max_hold: 2160h
```

- `Options.SupportDesks []supportcore.Desk` adds the host's desks, such as a
  PostHog Support desk, before mail.
- The mail desk uses the sender systemauthsvc already builds for verified
  email, which the service now keeps. A deployment without mail cannot
  enable support, and `New` says so.
- `Service.Support()` returns the package for the host.

ADR-019 makes support always on. In this release it is on whenever the
`support:` section is present, so a deployment that has not set a support
address keeps starting. A later release turns the missing section into a
startup error.

## Testing

- Unit tests with supportforge's in-memory store and desk, a fake
  `Requesters`, and a fake challenge: each route's success, every error
  status, the organization rules, the reply-address rule, rate limits, and
  that a response never carries text from a visitor.
- The SQL store on SQLite in unit tests, and on PostgreSQL in the existing
  integration workflow.
- Turnstile against `httptest`.
- systemauthsvc: configuration validation, migration of the new tables, and
  that the jobs start and stop.

## Later phases

- **Operators:** `support.request.read`, `support.desk.configure`, the
  `support_agent` role, list, read and redeliver, the CLI and the MCP server.
- **Organizations:** the index for owners and admins, shared text, and the
  sharing policy.
- **Governance:** holds (ADR-012), catalog registration (ADR-011), and export
  and erasure, once supportforge has them.
- **Replies:** drafts and approval.
