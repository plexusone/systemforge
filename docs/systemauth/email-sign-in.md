# Sign In with an Email Code

SystemAuth can sign people in with a one-time code mailed to them
([ADR-023](../design/adrs/ADR-023-email-code-sign-in.md)). It needs no
account at an upstream provider, so an application can launch before its
GitHub or Google app is reviewed, and it stays useful for people who have
neither. Applications federate to SystemAuth as they do for
[social login](social-login.md) and add no code of their own.

## How it works

1. The person chooses **Email** on SystemAuth's sign-in page (or the
   application sends them there with `idp_hint=email`) and enters an address.
2. SystemAuth mails a numeric code, through the configured
   [mail sender](verified-email.md#configuration), and shows a page to enter it.
3. The person enters the code in the same browser. A correct code proves the
   address. For an address with an account, that signs them in. For a new
   address, SystemAuth first asks for their name and, if they like, a name for
   their personal workspace, then creates the account and resumes the
   application's authorization request.

The name is never made from the address: SystemAuth asks for it, so the `name`
claim applications receive, and the name on public profiles and printed
certificates, is one the person chose (see
[names](#names)). The address becomes an `email` identity of the account. An existing account
with the same verified address (for example one created with GitHub) is
reached, not duplicated, and everything that applies to social sign-in applies
here too: the sign-up age question, invite codes and the waitlist, consent,
and the session.

## Configuration

Email sign-in needs the [`mail`](verified-email.md#configuration) section and
turns on with the presence of `social_login.email`. An empty section uses the
defaults:

```yaml
social_login:
  email: {}              # or set the values below
  # email:
  #   code_length: 6     # digits, 6 to 10
  #   code_lifetime: 10m # 5m to 30m
  #   max_attempts: 5    # entries per code, 3 to 10
mail:
  provider: smtp         # ses | smtp | log; see Resend, or Amazon SES
  from: "Example <no-reply@mail.example.com>"
  per_address: {requests: 5, period: 1h}
  per_client: {requests: 20, period: 1h}
```

No GitHub or Google provider is needed: with only `email`, SystemAuth's
sign-in page offers email. Production refuses the `log` mail provider, which
would write codes to the log.

| Setting | Default | Meaning |
|---------|---------|---------|
| `code_length` | 6 | Digits in the code. |
| `code_lifetime` | 10m | How long a code works. |
| `max_attempts` | 5 | Entries one code allows before it stops working. |
| `mail.per_address` | 5 an hour | Messages sent to one address. Also bounds how many live codes an address can have. |
| `mail.per_client` | 20 an hour | Messages one client address may cause to be sent. |

## Routes

| Route | Purpose |
|-------|---------|
| `GET /login/email?return_to=...` | The address form. |
| `POST /login/email` | Sends a code and shows the code page. |
| `GET /login/email/code` | The code form. |
| `POST /login/email/code` | Checks the code and signs in. |
| `POST /login/email/code/resend` | Sends a new code. |
| `GET /signup/name`, `POST /signup/name` | Asks a new account for its name; also used by social login when a provider gives none. |

`/oauth/authorize?...&idp_hint=email` goes straight to the address form when
email sign-in is configured, and to the chooser otherwise.

## Names

An email address says nothing about what to call someone, and an address is not
theirs to publish. So SystemAuth makes no name from it. When an account is about
to be created for a login with no name (every email sign-in, and a social login
whose provider gave neither a name nor a handle), it parks the proven sign-in
for 15 minutes, bound to the browser, and shows `/signup/name`:

- **Your name**, required, up to 100 characters, no `@`.
- **A name for your personal workspace**, optional, up to 80 characters; empty
  uses the person's name. The workspace's slug is generated, never made from
  the address.

Nothing is created until the form is answered, and answering uses the parked
sign-up once. A person who already has an account is not asked. Invites and the
minimum age come first, so a person who will be refused is not asked for a
name. The applications need no name prompt of their own for new accounts.

## What protects the code

A six-digit code can be guessed, so the controls carry the security:

- **Tries.** A code accepts `max_attempts` entries and then stops working.
  Each entry is counted before it is compared, in one atomic step, so
  parallel guesses cannot exceed the limit, on any number of instances.
- **Guesses per address.** A message that the address limit suppresses leaves
  a code no entry can match, so the mail limits also bound the live codes for
  an address. At the defaults that is 25 guesses per full quota of five
  messages, 2.5 in 100,000. The limit counts messages, not entries, and is
  shared across instances only when they share
  [rate limit storage](deployment.md#rate-limits).
- **One browser.** The code works only in the browser that asked for it.
- **Stored keyed.** The code is kept as an HMAC under a key derived from
  `tokens.hmac_secret`, bound to the browser and the address, never in
  the clear. Set `tokens.hmac_secret` (it is required in production), or codes
  do not survive a restart or another instance.
- **Used once, short lived.** A newer code replaces an older one; a replaced
  code cannot be used even if its replacement is not.
- **No account disclosure.** Asking for a code looks up no account, and
  known and unknown addresses get the same answers.
- **Origin and form checks** on every form.
- **A changed address retires the old one.** When a person changes their
  email, the `email` identity for the old address is removed in the same
  transaction, so the old mailbox no longer reaches the account. GitHub and
  Google identities stay.

Two costs follow from the limits. Someone who spends an address's hourly
messages can keep its owner from receiving a code for the rest of the hour.
And a message that is sent takes longer than one that is suppressed, so timing
shows that an address was recently mailed, though not whether it has an
account.

## Applications

An application that uses the [relying party BFF](relying-party.md) links to
`/bff/auth/email?return_to=/path`. The BFF forwards `idp_hint=email`, and
SystemAuth's own pages collect the address and the code. The application never
receives the code or handles the person's typing of it; it does receive the
verified address afterward, as identity data in the ID token and the user
profile, as it does for any provider. With `@plexusone/pages`, add `email` to the login page's
`oauthProviders`. Deploy SystemAuth and the BFF before listing `email` in an
application: an older BFF answers `UNKNOWN_PROVIDER`, and a SystemAuth
without the section shows its chooser.

## Operating it

Security events ([reference](../security/security-events.md)):

| Event | Meaning |
|-------|---------|
| `systemauth.email_code.sent` | A code was issued; `sent` is false when a limit suppressed the message or delivery failed. |
| `systemauth.email_code.exhausted` | A code used its tries without being entered correctly. Repeated, this is what guessing looks like. |
| `systemauth.sign_in` | Successes and refusals with method `email`; reasons `code_mismatch`, `code_unusable`, `stale_email_identity`. |

No event holds a code or an address. Watch for many `exhausted` events from
one client address, and for `sent` events with `sent: false`, which mean
limits or delivery problems.

Delivery is the part that can fail quietly. A person who does not get the
message cannot sign in, so keep the sending domain's SPF, DKIM and DMARC in
order and watch bounces and complaints at the provider. See
[Sending Mail with Resend](resend-deployment.md) or
[Amazon SES](ses-deployment.md).

## Limits of this method

Control of a mailbox is control of the account, as for any email-based
sign-in. Prefer it for launch and for people without a provider account, and
keep GitHub or Google for people who want them. A person's address can also
be changed from the signed-in account page; see [Verified Email](verified-email.md).
