# ADR-003: Verified Email in SystemAuth, Delivered Through omnimail

**Status:** Accepted
**Deciders:** @grokify
**Relates to:** ADR-002 (centralized social login via SystemAuth)

## Context

SystemAuth links an upstream GitHub/Google login to an existing principal by
email only when the provider asserts the email is verified, and creates a new
principal only with a verified email (ADR-002, `ResolveExternalLogin`). A user
whose provider email is unverified is therefore refused with no way forward.

Applications built on SystemForge that implemented social login themselves
link by email without any verification, which allows account takeover through
an unverified provider email. Every SaaS application needs a way to prove a
user controls an email address; building it per application repeats the
problem ADR-002 solved for login.

Sending email needs a delivery abstraction. The existing chat/messaging
abstraction (omnichat, including its Gmail provider) is built for
conversational messaging authenticated as a user, not for transactional
system email (verification links, notices) sent as the service.

## Decision

1. **SystemAuth owns email verification.** It issues single-use,
   short-lived, purpose-scoped verification tokens (stored only as hashes),
   sends a verification link, and on confirmation marks the principal's email
   verified. Relying parties inherit this through federation and read
   `email_verified` from ID tokens / UserInfo; they implement no mail flows.
2. **Scope: verification, not passwordless login.** Email links verify an
   address (unverified provider email at social login; email change). They do
   not sign a user in by themselves — GitHub and Google remain the sign-in
   methods. A verification link completes a pending social login only within
   the same browser session that started it.
3. **Delivery through `github.com/plexusone/omnimail`.** A small,
   vendor-free core module (message model, `Sender` interface, templates,
   SMTP and log/memory senders, a provider conformance suite). Vendor
   adapters live in the existing provider repositories: AWS SES in
   `omni-aws/omnimail` (first production provider), SendGrid in
   `omni-twilio/omnimail`, Gmail in `omni-google/omnimail`. SystemAuth
   depends only on the core `Sender` interface; the deployment chooses the
   adapter.

## Consequences

- One verified-email implementation for every SystemForge application; the
  account-takeover gap closes for apps that federate to SystemAuth.
- SystemForge gains a dependency on the small omnimail core module (no vendor
  SDKs); vendor SDKs are pulled in only by the deployment that selects them.
- Deliverability (SPF, DKIM, DMARC, bounce handling) is a deployment concern
  of the selected provider; SES is first.
- Abuse controls are required from day one: per-address and per-client
  rate limits on sends, token expiry (default 30 minutes), single use, and
  responses that do not reveal whether an address has an account.
- Passwordless magic-link sign-in remains possible later on the same token
  store, but is explicitly out of scope.
