# ROADMAP — Email One-Time Code Sign-In

**Initiative:** `INIT-SYSTEMFORGE-018`
**Repository:** `github.com/plexusone/systemforge`

Let people sign in to every federated application with a one-time code mailed
to them, so applications launch without waiting on provider app reviews
([ADR-023](../../../design/adrs/ADR-023-email-code-sign-in.md)). All mail goes
through `omnimail.Sender`, so the provider is configuration. Commits
implementing an item carry `Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — Code Sign-In in SystemAuth

**Theme:** A person signs in with an emailed code on the SystemAuth sign-in page

- [x] `RMI-SYSTEMFORGE-268` Verification token attempts: an attempt counter, an atomic check-and-count store method on the memory and Ent stores, and `storetest` conformance cases
- [x] `RMI-SYSTEMFORGE-269` The `social_login.email` configuration section (code length, code lifetime, attempt limit; an empty section enables it with defaults), validated, requiring `mail`; the production refusal of the `log` mail provider already covers it
  - Depends on: `RMI-SYSTEMFORGE-268`
- [x] `RMI-SYSTEMFORGE-270` The `sign_in_code` message (text and HTML) and the request, entry and resend routes, with keyed-hash storage, browser binding, send limits and no enumeration
  - Depends on: `RMI-SYSTEMFORGE-269`
- [x] `RMI-SYSTEMFORGE-271` A proven code resolves through `ResolveExternalLogin` as provider `email`: account creation behind the signup gate, linking by verified email, consent and session
  - Depends on: `RMI-SYSTEMFORGE-270`
- [ ] `RMI-SYSTEMFORGE-272` The chooser links to the email form (done with 270); still to do: `idp_hint=email` and email listed on the sign-in-methods page
  - Depends on: `RMI-SYSTEMFORGE-271`
- [x] `RMI-SYSTEMFORGE-273` Security events and OCSF mapping for code sent, failed and succeeded; per-client verification rate limit
  - Depends on: `RMI-SYSTEMFORGE-270`

## Phase 2 — Applications and Documentation

**Theme:** The applications turn it on and the docs describe it

- [ ] `RMI-SYSTEMFORGE-274` `email` as a provider in `@plexusone/auth` and `LoginPage`, sending `idp_hint=email` (systemforge-web)
  - Depends on: `RMI-SYSTEMFORGE-272`
- [ ] `RMI-SYSTEMFORGE-275` Guides: `docs/systemauth/email-sign-in.md`, updates to social login and verified-email docs, release notes
  - Depends on: `RMI-SYSTEMFORGE-272`
- [ ] `RMI-SYSTEMFORGE-276` End-to-end test through a relying party with the memory mail sender: request, code, session, authorization code
  - Depends on: `RMI-SYSTEMFORGE-271`
- [ ] `RMI-SYSTEMFORGE-278` Launch mail through Resend over SMTP: the Resend settings in the deployment guide, and a delivery check from the production domain
  - Depends on: `RMI-SYSTEMFORGE-275`
- [ ] `RMI-SYSTEMFORGE-277` Hosts enable it in their configuration with SES (host repositories)
  - Depends on: `RMI-SYSTEMFORGE-275`
