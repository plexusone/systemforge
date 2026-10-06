# ROADMAP — Verified Email for SystemAuth via omnimail

**Initiative:** `INIT-SYSTEMFORGE-006`
**Repository:** `github.com/plexusone/systemforge`

Design of record: [ADR-003](../../adrs/ADR-003-verified-email-via-systemauth-and-omnimail.md).
SystemAuth verifies that a user controls an email address (unverified provider
email at social login; email change) and delivers mail through the vendor-free
omnimail core, with AWS SES as the first production provider. Email links
verify addresses only; they are not a sign-in method. Commits implementing an
item carry `Refs: RMI-<REPOSLUG>-<NNN>`.

## Phase 1 — omnimail Core and SES

**Theme:** A vendor-free transactional email library with a first production provider

- [ ] `RMI-OMNIMAIL-001` Message model and Sender interface
  - `Message` (from, to/cc/bcc, reply-to, subject, text and HTML bodies, headers, tags), address validation, MIME assembly, `Sender.Send(ctx, Message) (SendResult, error)`, typed errors (invalid address, rejected, throttled, transient)
- [ ] `RMI-OMNIMAIL-002` Templates and built-in senders
  - text/html template pair rendering with safe defaults; SMTP sender (STARTTLS/TLS, auth); log and memory senders for development and tests
  - Depends on: `RMI-OMNIMAIL-001`
- [ ] `RMI-OMNIMAIL-003` Provider conformance suite
  - `providertest` package every adapter runs: addressing, bodies, headers, error classification, context cancellation
  - Depends on: `RMI-OMNIMAIL-001`
- [ ] `RMI-OMNIAWS-001` AWS SES v2 adapter for omnimail
  - `omni-aws/omnimail`: SES v2 SendEmail with configuration set and tags, throttling/transient error mapping, conformance suite against a fake SES endpoint
  - Depends on: `RMI-OMNIMAIL-003`

## Phase 2 — Email Verification in SystemAuth

**Theme:** SystemAuth proves address control once, for every application

- [ ] `RMI-SYSTEMFORGE-086` Verification token store
  - Single-use, purpose-scoped (`verify_email`, `email_change`) tokens stored as hashes with expiry (default 30 minutes); Ent and memory implementations with the shared store conformance suite; expired-row cleanup
  - Depends on: `RMI-OMNIMAIL-001`
- [ ] `RMI-SYSTEMFORGE-087` Verify-email step for social login
  - When the provider email is unverified, hold the login as pending, send a verification link, and on confirmation in the same browser session mark the email verified and complete account linking or creation; verify-email page with resend
  - Depends on: `RMI-SYSTEMFORGE-086`
- [ ] `RMI-SYSTEMFORGE-088` Email change with verification
  - Change the principal's email only after the new address is verified; notify the old address; revoke the pending change on cancel
  - Depends on: `RMI-SYSTEMFORGE-086`
- [ ] `RMI-SYSTEMFORGE-089` Mail configuration, templates, and abuse controls
  - `mail` config (provider: ses | smtp | log, from address, branding), branded verification templates, per-address and per-client send limits, responses that do not reveal account existence; production mode refuses the log sender
  - Depends on: `RMI-SYSTEMFORGE-087`
  - Depends on: `RMI-OMNIAWS-001`
- [ ] `RMI-SYSTEMFORGE-090` Verified-email propagation and documentation
  - `email_verified` and verification time in ID tokens and UserInfo; relying-party guide for reading it; deployment guide for SES (domain identity, DKIM, SPF, DMARC)
  - Depends on: `RMI-SYSTEMFORGE-089`
