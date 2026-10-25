# TRD — Invite-Gated Sign-Up

**Initiative:** `INIT-SYSTEMFORGE-013`
**Status:** Draft

## Current State

- `identity/signupgate` keeps email invites (`sf_signup_invites`) and the
  waitlist (`sf_signup_waitlist`). `Gate` implements `systemauth.SignupGate`:
  `AllowSignup` passes a verified email with a pending invite, and `SignedUp`
  marks the invite redeemed.
- The gate runs only in `gatedDirectory.CreateFromExternal`
  (`identity/systemauth/signup_gate.go`), when a social login matches no
  existing account. It sees the `ExternalLogin` and the request context, not
  the request.
- `AllowSignup` and `SignedUp` are separate, non-transactional steps around
  account creation. Nothing enforces a use count, and a failed creation after
  `AllowSignup` has nothing to undo, because `AllowSignup` only reads.
- `handleStart` (`GET /login/{provider}`) reads only `return_to`. The sign-up
  age question already carries flow data across the upstream round trip: a
  cookie set before login, read in the callback, and passed to a directory
  decorator as a context value (`signup_age.go`).
- `invited_by` is a free-text operator label. Nothing links an account to
  whoever invited it.
- Management is `signupcmd` (`systemauth invite`, `systemauth waitlist`),
  opening the database directly. There is no HTTP API.
- Platform admin is `sf_humans.is_platform_admin`, checked through
  `authz.PlatformAuthorizer`. Nothing grants it except database access or
  `principal.UpdateHuman`.
- systemauthsvc installs the gate and waitlist when `Options.InviteOnly` is
  set and exposes `SignupInvites()` and `SignupWaitlist()`.

## Design

### 1. Schema (`identity/ent/schema`)

New tables. All three are added to `multiapp.RestrictedSharedTables`, so no
application database login is granted them.

**`SignupCode`** (`sf_signup_codes`, `BaseMixin`):

| Field | Type | Notes |
| --- | --- | --- |
| `code_hash` | string, unique, sensitive | Hex SHA-256 of the normalized code |
| `code_hint` | string, 4 | Last four characters, for lists |
| `kind` | enum `operator`, `member` | Who created it |
| `label` | string, max 100, optional | Cohort name, such as `launch-week` |
| `note` | string, max 500, optional | Operator context |
| `created_by_principal_id` | uuid, optional | Creator, when created through the API |
| `created_by_label` | string, max 255, optional | Operator label, when created from the CLI |
| `max_uses` | int, ≥ 1 | |
| `use_count` | int, default 0 | Uses reserved or redeemed |
| `expires_at` | time, optional | |
| `revoked_at` | time, optional | |

Indexes on `created_by_principal_id`, `label`, `expires_at`.

**`SignupCodeRedemption`** (`sf_signup_code_redemptions`,
`TimeOrderedUUIDMixin`): `code_id` (edge to `SignupCode`, required),
`principal_id` (uuid, not a foreign key, so it survives deletion), `email`,
`created_at`. Index on `principal_id` and `code_id`.

**`SignupAllowance`** (`sf_signup_allowances`, `BaseMixin`): `principal_id`
(uuid, unique), `granted` (int, ≥ 0), `note` (max 500, optional),
`set_by_principal_id` (uuid, optional).

New columns, with `migrations/0011_signup_invite_attribution.sql` adding them
idempotently to existing databases:

- `sf_signup_invites.invited_by_principal_id` (uuid, optional)
- `sf_signup_waitlist.invited_at` (time, optional)

### 2. Codes (`identity/signupgate`)

**Format.** 16 characters from Crockford's base32 alphabet (80 bits), shown
as `XXXX-XXXX-XXXX-XXXX`. `NormalizeCode` upper-cases, drops dashes and
spaces, maps `O` to `0` and `I`/`L` to `1`, and refuses anything else.
Only the hash of the normalized code is stored; the code is returned once,
from `CreateCode`.

**`CodeStore`** over the identity Ent client:

```go
type CodeOptions struct {
    Kind               CodeKind   // CodeOperator or CodeMember
    Label, Note        string
    CreatedByPrincipal *uuid.UUID
    CreatedByLabel     string
    MaxUses            int        // ≥ 1
    ExpiresAt          *time.Time
}

func (s *CodeStore) CreateCode(ctx, CodeOptions) (Code, string, error) // the code value, shown once
func (s *CodeStore) ListCodes(ctx, CodeFilter) ([]Code, error)
func (s *CodeStore) RevokeCode(ctx, id uuid.UUID) error
func (s *CodeStore) Lookup(ctx, code string) (Code, error)       // for the sign-up page
func (s *CodeStore) Reserve(ctx, code string) (uuid.UUID, error)  // one use, atomically
func (s *CodeStore) Release(ctx, id uuid.UUID) error
func (s *CodeStore) Redeem(ctx, id, principalID uuid.UUID, email string) error
func (s *CodeStore) Redemptions(ctx, RedemptionFilter) ([]Redemption, error)
```

`Code` carries every field except the hash, plus `Status(now)`: `active`,
`used_up`, `expired`, or `revoked`.

**Reserve** is one conditional update:

```sql
UPDATE sf_signup_codes SET use_count = use_count + 1, updated_at = now
WHERE code_hash = $1 AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now) AND use_count < max_uses
```

One affected row means the use is reserved; none means the code is invalid
(`ErrCodeInvalid`, whatever the reason). **Release** decrements `use_count`
where it is above zero. **Redeem** inserts the redemption row. A process
that stops between reserve and redeem leaves a use counted without a
redemption, so a code can admit fewer accounts than its limit but never more.

### 3. Member allowances (`identity/signupgate`)

```go
type MemberOptions struct {
    DefaultAllowance int           // when a member has no allowance row; default 0
    CodeTTL          time.Duration // default 14 days
}

func (s *CodeStore) SetAllowance(ctx, principalID uuid.UUID, granted int, note string, setBy *uuid.UUID) error
func (s *CodeStore) Allowances(ctx) ([]Allowance, error)
func (s *CodeStore) MemberInvites(ctx, principalID uuid.UUID) (MemberSummary, error)
func (s *CodeStore) CreateMemberCode(ctx, principalID uuid.UUID) (Code, string, error)
```

A member's held count is their member codes that are redeemed, or neither
revoked nor expired. `CreateMemberCode` runs in a transaction that locks the
member's allowance row, creating it with the default when missing, and
refuses with `ErrAllowanceExhausted` when held ≥ granted. Member codes are
`kind = member`, `max_uses = 1`, and expire after `CodeTTL`. A member may
revoke only their own codes (`RevokeMemberCode(ctx, principalID, id)`).

### 4. The gate

`Gate` takes both stores. `AllowSignup` requires a verified email, then:

1. a pending email invite for the address allows the sign-up, using no code;
2. otherwise a code on the context (section 5) is reserved;
3. otherwise `ErrSignupNotInvited`.

`SignedUp` redeems whichever admitted the sign-up: the email invite as today
(also re-checking expiry), or the reserved code's redemption row.

**Undoing a reservation.** A new optional interface in `identity/systemauth`:

```go
// SignupGateAborter is implemented by a SignupGate that reserves something
// in AllowSignup. SignupAborted is called when account creation fails after
// AllowSignup succeeded.
type SignupGateAborter interface {
    SignupAborted(ctx context.Context, login ExternalLogin)
}
```

`gatedDirectory.CreateFromExternal` calls it when the wrapped directory
fails, which includes the age question (`errSignupAgeRequired`). The gate
releases the reserved use. The reservation is found again from the code on
the context, so no state is kept between calls.

### 5. Carrying a code through sign-in (`identity/systemauth`)

- `WithSignupCode(ctx, code) context.Context` and `SignupCodeFromContext(ctx)
  string` carry a normalized code to the gate.
- **Cookie.** `__Host-sf_signup_code` (no prefix over plain HTTP, as for the
  age cookies) holds the normalized code, HttpOnly, SameSite=Lax, one hour.
  The callback reads it into the context before `ResolveExternalLogin` and
  clears it once a login resolves to an account, new or existing. It survives
  the age question and a refusal, so the person can retry.
- **`GET /login/{provider}?invite_code=…`** sets the cookie before redirecting
  upstream, for hosts that link straight to a provider.
- **`GET /signup?code=…`** is a server-rendered page, like the waitlist page,
  registered when a code store is configured. A valid code sets the cookie and
  shows a button per provider, each going to `/login/{provider}` with
  `return_to` set to `SignupPage.ReturnTo`. An invalid code says only that the
  link is not valid and offers the waitlist. Wording comes from
  `SignupPage{Title, Message, InvalidNotice, ReturnTo}`; `ReturnTo` must pass
  the same redirect checks as `return_to`.
- `GET /signup` is rate-limited per client address with the waitlist's
  storage, so codes cannot be guessed through it.
- `WithSignupCodes(store SignupCodeLookup, page SignupPage) Option` installs
  the page; `SignupCodeLookup` is the one method the page needs.

### 6. HTTP API (`identity/signupgate/signupapi`)

`signupapi.New(Options) http.Handler`, a `net/http` ServeMux in the style of
`console`:

```go
type Options struct {
    Invites   *signupgate.Store
    Codes     *signupgate.CodeStore
    Waitlist  *signupgate.Waitlist
    Member    signupgate.MemberOptions
    Principal func(*http.Request) (uuid.UUID, error)         // the signed-in person
    IsAdmin   func(context.Context, uuid.UUID) (bool, error) // platform admin
    LinkBase  string // e.g. https://auth.example.com/signup, for invite links
    Audit     audit.Emitter
    Logger    *slog.Logger
}
```

Routes are relative to where the host mounts the handler. JSON is snake_case
like the rest of SystemAuth, lists are wrapped in a named key, and errors are
`{"error": "…"}`. Every response is `Cache-Control: no-store`, and
state-changing requests pass `http.CrossOriginProtection`.

| Method and path | Who | Does |
| --- | --- | --- |
| `GET /settings` | member | Default allowance, member code TTL, link base, whether the caller is an admin |
| `GET /admin/invites` | admin | Email invites (`?status=`) |
| `POST /admin/invites` | admin | `{emails, note, expires_in_days}` |
| `DELETE /admin/invites/{email}` | admin | Revoke |
| `GET /admin/codes` | admin | Codes (`?kind=&label=&status=`) |
| `POST /admin/codes` | admin | `{label, note, max_uses, expires_at}`; returns the code and link once |
| `POST /admin/codes/{id}/revoke` | admin | |
| `GET /admin/waitlist` | admin | Entries with `invited_at` |
| `POST /admin/waitlist/invite` | admin | `{emails, note, expires_in_days}`: email invites, entries marked invited |
| `DELETE /admin/waitlist/{email}` | admin | Remove |
| `GET /admin/allowances` | admin | Allowances with each member's email and held count |
| `PUT /admin/allowances` | admin | `{email, granted, note}` |
| `GET /admin/redemptions` | admin | Accounts by code, inviter, or label, joined with email invites |
| `GET /me/invites` | member | Allowance, held, and the caller's codes |
| `POST /me/codes` | member | Create a member code; returns the code and link once |
| `POST /me/codes/{id}/revoke` | member | Revoke one of the caller's codes |

A missing session is 401; an admin route for a non-admin is 403; a code or
allowance the caller may not touch is 404. Validation failures are 400.

**Audit events**, emitted through a nil-safe `emit` that never fails the
request: `signup_invite.created`, `signup_invite.revoked`,
`signup_code.created`, `signup_code.revoked`, `signup_allowance.set`,
`signup_waitlist.invited`, and from the gate `signup_code.redeemed`.

### 7. SystemAuth wiring (`identity/systemauthsvc`)

- `Options.SignupCodes bool` installs the code store, the `/signup` page, and
  the code-aware gate. It requires `InviteOnly`.
- `Options.MemberInvites signupgate.MemberOptions` and
  `Options.SignupPage systemauth.SignupPage`.
- `Options.SignupAPI bool` mounts `signupapi` at `/signup-invites/api/` on
  the SystemAuth host, with `Principal` from `CurrentLoginSession` and
  `IsAdmin` from the service's `PlatformAuthorizer`.
- `Service.SignupCodes() *signupgate.CodeStore` and
  `Service.SignupAPI(principal func(*http.Request) (uuid.UUID, error))
  http.Handler`, for a host that serves the API from its own server behind
  its own session.
- `Options.AuditEmitter` is passed to the API and the gate.

### 8. Commands

- `signupcmd.CodeCommand(open)`: `code create --label --max-uses
  --expires-in --note`, `code list [--all]`, `code revoke <id>`.
- `signupcmd.AllowanceCommand(open)`: `allowance set <email> <n>`,
  `allowance list`.
- `signupcmd.WaitlistCommand` gains `waitlist invite <email>... | --all`.
- `principal/admincmd.Command(open)`: `admin grant <email>`, `admin revoke
  <email>`, `admin list`, setting `is_platform_admin` through
  `principal.Service` so the graph is updated in rebac mode.
- `cmd/systemauth` registers all four.

### 9. Pages (`systemforge-web`, `@plexusone/invites`)

A new package, following `@plexusone/console`: a typed `api` over
`fetch` with `credentials: 'include'` and an `ApiError`, `useLoad`, and
`@plexusone/ui` components.

- `createInvitesApi(baseUrl)`: one method per route, snake_case wire types.
- `InviteAdminPage({ api })`: sections for Codes, Email invites, Waitlist,
  Allowances, and Joined (redemptions). New codes and links are shown once
  with a copy button. Revoking asks inline, as console does.
- `InvitePeoplePage({ api })`: the caller's allowance, a "Create invite link"
  button, the new link shown once with copy, and the caller's codes with
  status and revoke.
- The pages are plain components a host routes itself. They are not an
  `AppModule`, because `createHost` routes are organization-scoped and these
  pages are platform-wide.

## Testing Strategy

- **Store unit tests** on SQLite: format and normalization, hash-only
  storage, reserve to the limit, release, redeem, expiry, revoke, allowance
  counting with expired and revoked codes, and waitlist marking.
- **Concurrency:** many goroutines reserving a code with N uses admit exactly
  N (Postgres in CI where available, SQLite otherwise).
- **Gate tests** with a fake directory: invite before code, a failed creation
  releases its reservation, the age question releases and re-reserves.
- **Handler tests** for `/signup`, the cookie on `/login/{provider}`, and the
  callback carrying the code into the context.
- **signupapi tests** with `httptest`: 401, 403 and 404 paths, a member never
  sees another member's codes, codes shown only once, audit events emitted.
- **systemauthsvc** end-to-end: an invite-only service with codes admits a
  code holder and refuses once the code is used up.
- **Pages:** vitest with stubbed `fetch`, as in the console tests.
