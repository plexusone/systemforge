# ADR-018: The Organization Console on the SystemAuth Host

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-017 (decision 12: the connection interface is built once
over the SystemForge API), ADR-002 (the SystemAuth login session this
console signs in with), ADR-016 (no static API keys for callers of the
platform), ADR-015 (organizations are addressed by ID).
**Realizes:** the IAM console of INIT-SYSTEMFORGE-001 (Phase 2), and
decides where it is served and how it is authenticated.

## Context

An organization's administration does not belong to any one application.
Its connections to external services, its members and invitations, and its
roles and access are shared by every application the organization uses.
Integration platforms keep the same split: one place to connect an account,
and each feature only picks a connection.

Two things were open:

- **Where the pages live.** Each application could host its own copy, but
  that is the duplication ADR-017 decision 12 rules out, and an application
  that does not exist yet would have to repeat it.
- **How the pages call the platform.** The connections API takes an access
  token carrying `systemforge:connections:*`. An application's
  backend-for-frontend holds its own session, not such a token, and adding
  the scopes to every application's client is a change to each of them.

SystemAuth already has what an administration console needs: it is the
place every person signs in, it keeps a hardened login session on its own
host (`__Host-sf_login`, host-only, `HttpOnly`, `SameSite=Lax`), and the
organization services and the connections service run in its process.

## Decision

1. **One console, served by SystemAuth under `/console` on its own host.**
   It holds organization administration: connections first; members,
   invitations, roles and access (the IAM console) join it. Applications
   link to it and do not host their own administration pages.
2. **The console signs in with the SystemAuth login session.** No OAuth
   client and no access token reach the browser. A page load without a
   session redirects to `/login?return_to=<console path>`, as consent does.
3. **Scopes do not apply to the console; roles do.** Scopes limit what a
   person delegates to a client. The console is SystemAuth's own interface
   acting as the signed-in person, so it delegates nothing. Every request is
   authorized exactly as any other caller's: by the person's organization
   role, resource grants and the platform's authorizer, with the
   organization in the path as the row-level security tenant.
4. **Same operations, another entrance.** The console mounts the existing
   handlers, such as the connections API, under `/console/api` with a
   session authenticator instead of a bearer authenticator. Each operation
   has one implementation, one authorization path and one audit trail.
5. **Cross-site requests are refused.** State-changing requests pass Go's
   `http.CrossOriginProtection`, which accepts only same-origin requests
   (by `Sec-Fetch-Site`, or `Origin` against the host), and bodies are JSON.
   With a host-only `SameSite=Lax` session cookie, a page on another site
   can neither send a state-changing request with the session nor read a
   response.
6. **The pages are a static build served from a configured directory.**
   `@plexusone/console` in systemforge-web builds them; the host
   application builds them with its own chrome and points SystemAuth at the
   output (`console.web_dir`). Every path under `/console/` that is not a
   file serves `index.html`, which is never cached. Pages are served with a
   restrictive content security policy and may not be framed.
7. **Applications link in with a return address.** A link such as
   `/console/orgs/{org}/connections/new?provider=cloudflare&return_to=<url>`
   opens the connect wizard and returns to the application when the person
   is done. `return_to` passes the same allow-list as sign-in redirects.
8. **The console is off unless configured,** and its connections section is
   present only when connections are enabled (ADR-017).

## Consequences

- **One place to administer an organization,** for every application and
  for applications not yet built.
- **No scope work in applications** to manage connections. The connections
  API with `systemforge:connections:*` remains for clients that call it
  themselves, such as agents and automation.
- **Console sessions are SystemAuth sessions.** Signing out of SystemAuth
  ends them; their lifetime is the login session's.
- **The console's host is the issuer's host.** A deployment that puts
  SystemAuth behind a separate domain serves the console there too.
- **The pages are built outside SystemForge.** A deployment that wants the
  console builds `@plexusone/console` (or its own pages over the same API)
  and configures the directory.

## Alternatives considered

- **A page in each application, through its backend.** Duplicates the
  interface per application and grows each backend with administration
  calls; rejected by ADR-017 decision 12.
- **A separate console application with its own client and session.** Adds
  an OAuth client, a backend-for-frontend and a host to run the same calls
  SystemAuth can serve in process.
- **Access tokens in the browser.** A single-page application holding a
  bearer token with administration scopes is exposed to any script that
  runs on its origin; a host-only `HttpOnly` session is not.
