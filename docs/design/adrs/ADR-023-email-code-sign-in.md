# ADR-023: Email One-Time Code Sign-In in SystemAuth

**Status:** Accepted
**Deciders:** @grokify
**Relates to:** ADR-002 (centralized social login), ADR-003 (verified email via omnimail)

## Context

SystemAuth signs people in with GitHub and Google only. Each provider needs an
app review before it serves the public, and several applications launch at
once. ADR-003 left passwordless sign-in out of scope but kept it possible on
the same token store. Email sign-in lets applications launch without waiting
on provider reviews, and remains useful afterwards for people with neither
account.

Applications federate to SystemAuth as OIDC clients, so sign-in methods belong
in SystemAuth. An application gains a method without code of its own.

## Decision

1. **SystemAuth adds email one-time code sign-in.** On the sign-in page a
   person enters an email address, SystemAuth mails a short numeric code, and
   the person types it into the SystemAuth page in the same browser. The code
   proves control of the address; SystemAuth then resolves the principal and
   starts the session exactly as for social login.
2. **Code first; links later if needed.** A code works across devices, and
   mail scanners that prefetch links cannot spend it. A mailed link remains
   possible on the same pending record.
3. **Same identity pipeline as social login.** A proven code produces an
   `ExternalLogin` with `Provider: "email"`, the normalized address as
   `Subject` and `EmailProven: true`, passed to `ResolveExternalLogin`. Linking
   by verified email, the signup gate (age, invite code, waitlist), consent,
   audit events and `sf_principal_id` as the OIDC `sub` apply unchanged. A
   person who signed up with GitHub and later uses email at the same address
   reaches the same principal.
4. **Mail goes through omnimail only.** Sending uses the existing
   `mail.send` path and the `omnimail.Sender` interface (ADR-003). Library
   packages import no vendor SDK. The provider (`ses`, `smtp`, `log`, or any
   other `Sender` passed as `Options.MailSender`) is deployment configuration,
   so swapping providers changes no sign-in code. A new message kind
   (`sign_in_code`) is added to the built-in templates.
5. **Launch provider: Resend over SMTP, no adapter needed.** The omnimail
   core's SMTP sender serves any provider that offers SMTP, so a host can
   launch with `mail.provider: smtp` pointed at Resend's SMTP endpoint (user
   `resend`, the API key as the password from the environment) and move to SES
   or SendGrid later by changing configuration. A native Resend adapter on
   its HTTP API (in its own `omni-*` repository, passing the
   `providertest` conformance suite) is optional and only worth building if
   SMTP proves limiting, for example for delivery webhooks or tags. The sending
   domain still needs SPF and DKIM records; that is DNS setup, not a review.
6. **Configured, off by default.** A `social_login.email` section enables the
   method and requires the `mail` section. The chooser shows an email form
   next to the provider links, and `idp_hint=email` selects it. Production
   refuses the `log` provider, as for verification mail.

## Abuse controls

A 6-digit code has about 20 bits of entropy, so the controls carry the
security, not the code:

- **Bound to the browser.** The code is accepted only with the cookie of the
  browser that asked for it (same binding as pending sign-ins).
- **Attempt limit.** Five wrong entries destroy the code. The counter is
  updated atomically with the check, so concurrent guesses cannot exceed it.
  This needs an attempts field on the verification token and a store method;
  the `storetest` conformance suite gains cases for it.
- **Short life, single use.** Codes expire in 10 minutes (configurable 5m to
  30m) and work once. A newer code revokes older ones for the browser.
- **Keyed hash at rest.** A code is stored as an HMAC under the server's
  secret (`tokens.hmac_secret`), never a bare SHA-256, since the small code
  space makes an unkeyed hash reversible from a database copy.
- **Send limits.** The existing `per_address` and `per_client` limits apply;
  a used-up address limit suppresses the message and the response stays the
  same. Verification attempts are rate limited per client address as well.
- **Guesses are bounded per address, not only per code.** A suppressed
  request still stores a code, but one no entry can match (not digits, 128
  random bits). Without that, anyone could make unlimited live codes for an
  address, each with fresh tries, and the mail limits would not cap the
  guessing. With it, live codes for an address are the mailed ones, so the
  guesses are bounded per batch of sends: each send the address limit allows
  (5 an hour by default) gives one code with 5 tries, so 25 guesses, 2.5 in
  100,000, per full quota. The limit counts sends, not entries, so this is not
  a strict hourly cap on guesses: tries on one batch can fall in the same hour
  as tries on the next once the earlier sends leave the limiter's window. The
  quota is shared across replicas only when they share rate limit storage.
  The same limit lets an attacker keep a victim from receiving codes for an
  hour by spending the address's sends; that cost is
  accepted, as it is for verification links.
- **No enumeration.** Responses and timing do not reveal whether an address
  has an account.
- **Same-origin POSTs with CSRF tokens**, as the verify-email pages.
- **Audit events** `systemauth.email_code.sent` (with whether it was sent),
  `systemauth.email_code.exhausted` (a code used up its tries), and the
  existing `systemauth.sign_in` events for each refusal (`code_mismatch`,
  `code_unusable`, `stale_email_identity`) and success (method `email`),
  through the security event log and OCSF emitter. No event holds a code or
  an address.
- **Address handling.** Addresses are parsed with `omnimail.ParseAddress`,
  lowercased and length limited. Plus-addressing is preserved, since stripping
  it would merge distinct mailboxes at some providers.

## Consequences

- Applications launch with email sign-in without provider app reviews and
  without code changes beyond the sign-in page. The chooser is SystemAuth's own,
  so every federated application gets it together.
- Email becomes a sign-in method on the sign-in-methods page, listed beside
  the linked providers.
- Control of a mailbox is control of the account. This holds for every
  email-based method; operators keep deliverability (SPF, DKIM, DMARC) in
  order, and the existing disabled-principal and access-invalidation paths
  apply.
- The login-card/`LoginPage` components in systemforge-web gain `email` as a
  provider that redirects with `idp_hint=email`; the code entry itself is a
  SystemAuth page, not a web component.

## Alternatives considered

- **Magic link only.** Fails when the link opens on another device or in a
  mail client's in-app browser, and needs scanner-safe confirmation. Kept as a
  possible later addition.
- **Each application implements email login.** Repeats the problem ADR-002
  solved and gives each application its own account-takeover surface.
- **Passwords.** More surface (storage, reset, breach handling) for no launch
  benefit.
