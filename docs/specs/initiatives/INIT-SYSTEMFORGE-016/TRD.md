# TRD — Support Requests and Feedback

**Initiative:** `INIT-SYSTEMFORGE-016`

The decisions are in ADR-019. This document says how the first release
builds them: intake, delivery, clearing and the form. Agent tools, the organization
view, replies, holds and catalog registration come in later phases
([ROADMAP](ROADMAP.md)).

## Package

`support` composes [supportforge](https://github.com/plexusone/supportforge)
with the platform, as `connections` does for connectforge. It depends on
`supportforge`, `supportforge/store/sqlstore`, `supportforge/maildesk` and
`supportforge-core`, and nothing in supportforge depends on SystemForge.

SystemForge ships no help-desk adapters and no bot challenge. They
implement supportforge-core's `Desk` and supportforge's `ChallengeVerifier`,
and the host passes them in, so an application can compose integrations
that live in its own or a private module.

```text
support.Open(Options)
  ├── sqlstore.Store            (supportforge_* tables on the platform database)
  ├── supportforge.Service      (intake, outbox, worker, status, clearing)
  │     ├── Desks               host desks first, then the mail desk if mail is set
  │     ├── ChallengeVerifier   the host's, for visitors
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

	// Desks are tried in order, then the mail desk when Mail is set. At
	// least one desk is required.
	Desks []supportcore.Desk
	Mail  *MailDesk // the support inbox and the sender; optional

	Requesters Requesters        // resolves a principal's verified email and memberships; required
	Challenge  supportforge.ChallengeVerifier // the host's; without it visitors are refused
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
| `POST /api/v1/public/support/requests` | visitor | none; the host's challenge, and mounted only with one |

**A signed-in request.**

- The requester comes from the token and `Requesters`, never from the body:
  the principal, the verified email as the reply address, and the
  organization.
- The body may name an organization, which must be one the principal belongs
  to. Without one, a principal in exactly one organization gets it, and
  otherwise the request has none.
- A principal without a verified email may still send feedback with no
  reply wanted. A request wanting a reply is refused with 422.

**A visitor request** carries the reply address and a challenge token,
which the host's `ChallengeVerifier` checks. Without a verifier the route is
not mounted. It
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
  clear_delay: 168h
  max_hold: 2160h
```

- `Options.SupportDesks []supportcore.Desk` adds the host's help desks,
  such as a PostHog Support desk, tried in order before mail. Their
  credentials are the host's.
- `Options.SupportChallenge supportforge.ChallengeVerifier` enables visitor
  requests, with a challenge such as Cloudflare Turnstile. Its secrets are
  the host's to configure.
- The mail desk uses the sender systemauthsvc already builds for verified
  email, which the service now keeps. It is added only when the deployment
  configures mail; `inbox` and `from` are then required.
- **Without mail,** the host's desks are the only desks, and at least one is
  required. A request every desk refuses stays in the outbox and is retried;
  the observer and the logger report it, so a deployment can alert on
  requests waiting too long. Nothing is lost, but nothing reaches the
  operator until a desk accepts it.
- `Service.Support()` returns the package for the host.

ADR-019 makes support always on, in two steps. In this release it is on
whenever the `support:` section is present, so a deployment that has not set
a support address keeps starting. A later release turns the missing section
into a startup error.

## Mail cap

Outbound mail can cost money, and the visitor form sends acknowledgments to
addresses nobody has verified. A hard cap, set by the deployment and changed
by an app administrator, stops every message once it is reached. It covers
all of systemauthsvc's mail, not only support.

### Where it sits

systemauthsvc wraps its mail sender in a capped sender before anyone uses
it, so address verification, the mail desk and acknowledgments all pass
through it. The wrapper is a small omnimail decorator over a `Counter` port;
SystemForge supplies a counter on the platform database, so the cap holds
across instances and restarts.

### Limits

| Limit | Meaning |
| --- | --- |
| `monthly` | Messages in a UTC calendar month, all kinds together |
| `daily` | Messages in a UTC day, all kinds together |
| `per_recipient_daily` | Messages to one address in a UTC day |
| `kinds.<kind>.daily` | Messages of one kind in a UTC day |

Every message carries a kind: `auth` (address verification and other
account mail), `support_desk` (a request to the support inbox) and
`support_ack` (an acknowledgment). A kind's own limit keeps visitor
acknowledgments from using up the allowance that sign-in needs.

```yaml
mail:
  limits:
    monthly: 10000
    daily: 1000
    per_recipient_daily: 5
    kinds:
      support_ack: { daily: 200 }
```

There is no unlimited setting. A deployment that leaves `limits` out gets
these defaults, and a limit of zero stops that mail entirely.

### Counting

- A message is counted when it is reserved, before it is sent, by an atomic
  increment that succeeds only below the limit. A failed send still counts,
  so retries cannot get round the cap.
- If the counter cannot be read or written, nothing is sent. The cap fails
  closed.
- Counts are kept per period and kind, and per recipient as a keyed hash of
  the address, never the address itself. Rows older than two months are
  deleted by a daily job that systemauthsvc runs with its own jobs, since
  the cap covers all its mail, not only support.

### When a limit is reached

- The sender returns `omnimail.ErrLimitReached` and sends nothing.
- **Support requests are not lost.** The mail desk reports the error as
  retryable, so the request stays in the outbox until the period resets or
  the cap is raised. The host's desks earlier in the order do not use our
  sender and keep working.
- **Acknowledgments are skipped,** not queued, and the case records it.
- **Address verification fails with a clear message** to the user that mail
  cannot be sent right now.
- The audit log and the platform logger record the first refusal in each
  period, and the usage endpoint shows it. Alerts at 80% and 100% go to the
  operator's alerting, never by email, which the cap may be blocking.

### Administration

An app administrator sees usage and changes the limits without a deploy.

| Method and path | Permission |
| --- | --- |
| `GET /api/v1/admin/mail/usage` | `mail.limits.read` |
| `PUT /api/v1/admin/mail/limits` | `mail.limits.configure` |

- The configured limits are the starting values. A change by an
  administrator is stored in the platform database, applies to every
  instance within a minute, and is audited with who changed what.
- Both permissions belong to the platform administrator role. Organization
  administrators have neither.
- The console shows usage against each limit for the day and the month.

### Outside the application

The cap protects against abuse through the application. Cost control itself
sits below SystemForge, at the infrastructure level: the operator may run
a program that watches the account's usage and, at a limit, turns the
provider's sending off or denies it to the sending role. SystemForge does not run it, configure it or release
it, and cannot override it; its calls to the provider simply start failing.

SystemForge only has to fail cleanly when that happens. An access-denied or
sending-disabled answer from the provider is classified by the omnimail
sender as `ErrSendingBlocked` and handled exactly like `ErrLimitReached`:
support requests wait in the outbox, acknowledgments are skipped, and
address verification tells the user mail cannot be sent right now.

## Testing

- Unit tests with supportforge's in-memory store and desk, a fake
  `Requesters`, and a fake challenge: each route's success, every error
  status, the organization rules, the reply-address rule, rate limits, and
  that a response never carries text from a visitor.
- The SQL store on SQLite in unit tests, and on PostgreSQL in the existing
  integration workflow.
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

## User interface

`@plexusone/support` in systemforge-web (ADR-019 decision 10): the support
button and panel, with "Contact support" and "Send feedback", and "My
requests". It calls the API above with the session, loads no vendor script
and stores nothing in the browser. A visitor form takes the host's
challenge widget as a prop, so the package names no challenge vendor.
