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
| `ses` | Amazon SES v2. The `systemauth` binary builds the sender from `mail.ses` with the AWS default credential chain. |
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
