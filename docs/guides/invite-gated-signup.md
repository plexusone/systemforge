# Invite-Gated Sign-Up

A deployment launching to a small audience can grow on purpose: first the
people its operators know by name, then people those early members vouch
for, then larger cohorts. Invite-only sign-up does this with three kinds of
invite, all needing a verified email from the upstream provider:

| Invite | Created by | Admits | Shared as |
| --- | --- | --- | --- |
| **Email invite** | Operator | The one address it names | Nothing to share: the person signs in with that address |
| **Operator code** | Operator | Up to its use limit, whoever holds it | A link |
| **Member code** | Member, from their allowance | One person | A link |

People who already have an account always sign in as before. A refused
sign-up is never told why, and lands on the waitlist.

## What an invited person sees

1. They open an invite link, `https://auth.example.com/signup?code=…`.
2. SystemAuth shows **You're invited** with a button per provider. A code
   that cannot be used (used up, expired or revoked) gets one notice, whatever
   the reason, and a link to the waitlist.
3. They sign in with the provider. If they have no account, the code admits
   them and their account is created; they land on the application.

The code is kept in a cookie for an hour, so answering the
[sign-up age question](signup-age.md) in between does not lose it. A person
invited by address does not use up a code they also hold.

## Turning it on

In a host binary, on `systemauthsvc.New`:

```go
svc, err := systemauthsvc.New(ctx, cfg, systemauthsvc.Options{
    InviteOnly:  true,
    SignupCodes: true, // invite codes and the /signup page
    SignupPage: systemauth.SignupPage{
        ReturnTo: "https://app.example.com/", // where people land after signing in
    },
    MemberInvites: signupgate.MemberOptions{
        DefaultAllowance: 0,                   // members invite nobody until allowed
        CodeTTL:          14 * 24 * time.Hour, // how long a member's code works
    },
    SignupAPI:    true, // the invite API at /signup-invites/api
    AuditEmitter: auditEmitter,
})
```

`ReturnTo` must be on an allowed redirect origin
(`social_login.allowed_redirect_origins`). With a relying-party application,
point it at the application's sign-in URL: the person is already signed in
to SystemAuth, so the application's own sign-in completes at once.

Links that start at a provider directly can carry the code too:
`/login/google?invite_code=…&return_to=…`.

## Operating from the command line

The commands read the configured database directly, so they work with the
server running and before any administrator exists.

```bash
systemauth admin grant ops@example.com      # the person signs in once first
systemauth invite add ada@example.com --note "known personally"
systemauth code create --label launch-week --max-uses 50 --expires-in 336h
systemauth code list                        # usable codes; --all for every code
systemauth code joined --label launch-week  # accounts created with a label's codes
systemauth code revoke <id>
systemauth allowance set ada@example.com 3  # Ada may invite three people
systemauth allowance set ada@example.com default
systemauth waitlist invite --all            # email invites for everyone waiting
```

A new code is printed once, with its link. Only a hash is stored, so copy it
when it is created; a lost code is revoked and replaced.

## Member invites

A member may hold codes up to their allowance: an operator sets it per
member, or `MemberInvites.DefaultAllowance` applies. Codes already used, and
codes still usable, count against it, so revoking or letting an unused code
expire gives its slot back. A member sees only their own codes.

## The invite API

`signupapi` serves operator and member routes. `Options.SignupAPI` mounts it
on the SystemAuth host for the SystemAuth login session. A host application
that embeds SystemAuth and has its own session serves the same API itself,
so its pages stay same-origin:

```go
api, err := svc.SignupAPI(func(r *http.Request) (uuid.UUID, error) {
    return mySession.PrincipalID(r) // the person signed in to the host
})
mux.Handle("/invites/api/", http.StripPrefix("/invites/api", api))
```

| Method and path | Who | Does |
| --- | --- | --- |
| `GET /settings` | member | Default allowance, member code TTL, sign-up URL, whether the caller is an administrator |
| `GET /me/invites` | member | The caller's allowance, held count and codes |
| `POST /me/codes` | member | Create a member code; the code and link are returned once |
| `POST /me/codes/{id}/revoke` | member | Revoke one of the caller's codes |
| `GET`, `POST /admin/invites`; `DELETE /admin/invites/{email}` | admin | Email invites |
| `GET`, `POST /admin/codes`; `POST /admin/codes/{id}/revoke` | admin | Operator codes |
| `GET /admin/waitlist`; `POST /admin/waitlist/invite`; `DELETE /admin/waitlist/{email}` | admin | The waitlist |
| `GET`, `PUT /admin/allowances` | admin | Member allowances |
| `GET /admin/joined` | admin | Accounts admitted by codes and email invites, filtered by `code_id`, `label` or `inviter` |

Operator routes are for platform administrators. JSON is snake_case, errors
are `{"error": "…"}`, responses are not cached, and writes from another
origin are refused. Every change is sent to the audit emitter:
`signup_invite.created`, `signup_invite.revoked`, `signup_code.created`,
`signup_code.revoked`, `signup_code.redeemed`, `signup_allowance.set` and
`signup_waitlist.invited`.

## Guarantees and limits

- **Use limits hold under concurrency.** A code is reserved with one
  conditional update before the account is created, and given back if
  creation fails. If the process stops in between, the use stays counted, so
  a code can admit fewer people than its limit but never more.
- **Guessing is impractical.** Codes carry 80 random bits, and the sign-up
  page is rate-limited per client address.
- **Other account paths are not gated.** SCIM, federation sync, managed
  principals and `signup.Service` create accounts without invites, as before.
- **Nothing is emailed.** Operators and members share links themselves.
