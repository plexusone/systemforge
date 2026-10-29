# Verified Email

SystemAuth proves that a person controls an email address, once, for every
application that federates to it
([ADR-003](../design/adrs/ADR-003-verified-email-via-systemauth-and-omnimail.md)).
It sends a single-use link and, when the link is opened, marks the address
verified. Relying parties read the result from the ID token and UserInfo;
they implement no mail flows of their own.

Email links verify an address. They are **not** a way to sign in: GitHub and
Google remain the sign-in methods.

## Configuration

Verification mail is off until the configuration has a `mail` section, which
needs `social_login`:

```yaml
mail:
  provider: ses                 # ses | smtp | log
  from: "Example <no-reply@example.com>"
  reply_to: support@example.com # optional
  product_name: Example         # default: the issuer host
  support_url: https://example.com/help  # optional, https
  token_lifetime: 30m           # 5m to 24h; default 30m
  per_address: {requests: 5, period: 1h}
  per_client: {requests: 20, period: 1h}
  ses:
    region: us-east-1
    configuration_set: systemauth-transactional
```

| Provider | Delivery |
|----------|----------|
| `ses` | Amazon SES v2. The `systemauth` binary builds the sender from `mail.ses` with the AWS default credential chain; see [Sending Mail with Amazon SES](ses-deployment.md). |
| `smtp` | An SMTP server, `mail.smtp` (`host`, `port`, `security: starttls\|tls\|none`, `username`, `password`). Credentials are never sent without TLS. |
| `log` | Writes each message, link included, to the server log. Development only. |

Keep the SMTP password out of the file: `password: ${SYSTEMAUTH_SMTP_PASSWORD}`
is expanded from the environment, as are the other secrets.

Mail is delivered through the vendor-free
[omnimail](https://github.com/plexusone/omnimail) `Sender` interface. The
library packages (`identity/systemauth`, `identity/systemauthsvc`) depend
only on it; the AWS SDK is linked only into a binary that selects SES.

- `systemauthsvc.New` builds the `log` and `smtp` senders from the
  configuration. For `ses`, or any other provider, pass the sender as
  `Options.MailSender`.
- An application embedding `systemauth` directly passes its sender with
  `systemauth.WithMailSender`; `NewEmbedded` refuses a `mail` section
  without one.

Verification tokens are stored in `sf_verification_tokens` when the server
uses `EntStorage` (otherwise in memory, for one instance), or in the store
passed with `WithVerificationTokenStore`.

### Messages

The messages are built in and branded with `product_name` and, when set, a
help link to `support_url`. Each has a plain-text and an HTML part; the HTML
part is rendered with `html/template`, so every value is escaped for its
context. Messages carry the SES message tag `systemauth` naming the kind
(`verify_sign_in`, `verify_email_change`, `email_change_requested`,
`email_changed`), for event destinations on the configuration set.

### Abuse controls

- **Single use, short lived, purpose scoped.** A link works once, expires
  after `token_lifetime`, and is accepted only for the purpose it was issued
  for (`verify_email` or `email_change`). Only a SHA-256 hash of the token is
  stored. Confirmation is one conditional update, so two concurrent
  confirmations cannot both succeed.
- **Bound to who asked.** A link completes only what the browser or account
  that asked for it started (see the flows below); a link alone does
  nothing.
- **Confirmed by a form, not by opening the link.** Opening a link shows a
  page with a button; only that `POST`, origin-checked and carrying a
  CSRF token, uses the token, so mail scanners that fetch links do not burn
  it.
- **Send limits.** `per_client` bounds the messages one client address may
  cause to be sent (answered with `429` when used up); `per_address` bounds
  the messages sent to one address. A used-up address limit only suppresses
  the message: the response is the same as when it is sent. Both use the
  [rate limit storage](deployment.md#rate-limits), so several instances need
  it shared.
- **No account enumeration.** Responses never say whether an address
  belongs to an account, and the same page is shown whether or not a message
  was sent or delivered. Delivery failures are logged, not shown.
- **Production refuses the log provider.** Outside development mode the
  server does not start with `provider: log`, or with an omnimail log sender
  passed in, and there is no waiver: the log sender writes links that
  complete sign-ins and email changes to the server log.

## Unverified provider email at sign-in

Without mail, a GitHub or Google sign-in whose provider email is not
verified is refused (`ErrEmailNotVerified`). With mail, it is held instead:

1. The callback stores the pending sign-in (provider identity, email, name,
   where to return) with a `verify_email` token and sets the
   `__Host-sf_verify_email` cookie (`HttpOnly`, `Secure`, `SameSite=Lax`,
   host-only) in the browser that started it. The token's binding is a
   SHA-256 hash of that cookie. Nothing about the sign-in is kept in the
   browser.
2. SystemAuth mails a link to `/login/verify-email/confirm?token=…` and sends
   the browser to `/login/verify-email`, which names the address and offers
   **Send another link** (`POST /login/verify-email/resend`). A resend
   replaces the earlier links.
3. Opening the link shows a confirmation form. Its `POST` uses the token only
   together with the pending sign-in's cookie, from the issuer's origin and
   with a CSRF token derived from the cookie. In another browser the link
   only explains that it must be opened where the sign-in started.
4. On confirmation the address counts as proven (`ExternalLogin.EmailProven`)
   and the sign-in completes through `ResolveExternalLogin`, with the same
   invite, age and conflict rules as any other sign-in.

| Route | Purpose |
|-------|---------|
| `GET /login/verify-email` | The pending sign-in's "check your email" page |
| `POST /login/verify-email/resend` | Mail a new link, within the send limits |
| `GET /login/verify-email/confirm?token=` | The mailed link: a confirmation form |
| `POST /login/verify-email/confirm` | Use the token and complete the sign-in |

### Linking to an existing account

A proven email counts as verified **and** authoritative, so it may create an
account or link the provider identity to an existing account whose own
email is verified and equal to it, as an authoritative Google email does.
This is acceptable only because the person proved control of the mailbox in
this sign-in, in the browser that started it, within `token_lifetime`; it is
the same trust a password reset by email places in the mailbox. An account
whose email is not verified is never linked: the sign-in is refused as a
conflict, and the person signs in the way they did before.

### Why someone else's link or pending sign-in is useless

- The token is bound to a hash of the pending sign-in's cookie, a 256-bit
  random value in an `HttpOnly`, `__Host-` cookie. Someone who obtains the
  link (a forwarded message, a mail scanner, a shared mailbox) cannot use it
  without that browser's cookie.
- Someone who starts a sign-in with *their* provider account and *your*
  address sends the link to your inbox; opening it in your browser does
  nothing, because your browser does not hold their pending sign-in. Your
  click cannot complete their sign-in.
- A confirmation with the wrong cookie does not use the token, so an
  attacker cannot burn your link either.

## Changing an email address

With mail configured and a principal directory that implements
`PrincipalEmailChanger` (the Ent and memory directories do), a signed-in
person manages their email at `/account/email`:

1. **Request.** `POST /account/email` with the new address mails an
   `email_change` link to the **new** address and a notice to the **current**
   one, naming the new address masked (`n***@example.com`) and pointing at
   the page where the change can be cancelled. A new request replaces the
   pending one. The answer is the same whether or not the new address belongs
   to another account, could be sent to, or was within its send limit.
2. **Confirm.** The link opens a confirmation form; its `POST` uses the token
   only from a session of the principal that asked, so a link opened while
   signed in as someone else, or signed out, does nothing (signed out, the
   page asks the person to sign in and open the link again). The email
   changes, marked verified at that moment (`email_verified_at`), only if it
   is still the address the change was requested from and no other account
   has the new one; otherwise nothing changes and the page says the address
   cannot be used. A notice that the email was changed goes to the old
   address.
3. **Cancel.** `POST /account/email/cancel` revokes the pending change; its
   link stops working.

| Route | Purpose |
|-------|---------|
| `GET /account/email` | The current email, a pending change, and the change form |
| `POST /account/email` | Request a change |
| `POST /account/email/cancel` | Cancel the pending change |
| `GET /account/email/confirm?token=` | The link mailed to the new address: a confirmation form |
| `POST /account/email/confirm` | Use the token and change the email |

All `POST`s are origin-checked and carry a CSRF token derived from the login
session. Managed principals (ADR-009) cannot change their email here; their
managers do. The change records `systemauth.email_change.requested`,
`systemauth.email_change.cancelled`, `systemauth.email.verified` and
`systemauth.email.changed` [security events](../security/security-events.md),
none of which records an address.

The principal's identifier, which is its email for a person, changes with
it. Relying parties see the new address in the next ID token or UserInfo
response; one that keys accounts by email should key them by `sub` instead.

## What relying parties receive

With the `email` scope, ID tokens and UserInfo carry `email`,
`email_verified` and, as a SystemForge extension, `email_verified_at`: when
the current address was verified, as a NumericDate. It is set when an
account is created with a verified email, when a sign-in proves the address
with a link, and when an email change is confirmed. See
[Reading email verification](relying-party.md#reading-email-verification).
