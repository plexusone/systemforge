# PRD — Application Authentication

**Initiative:** `INIT-SYSTEMFORGE-014`
**Status:** Draft
**Home repo:** `github.com/plexusone/systemforge`
**Target release:** v0.26.0
**Builds on:** `identity/relyingparty`, `identity/requestprincipal`, DPoP-bound
tokens (v0.21), `relyingparty.Client.Transport` (v0.25)

## Problem

An application that signs people in through SystemAuth is a relying party.
`identity/relyingparty` gives it the parts: a client, the `/bff/*` cookie
session, a middleware for access tokens, membership sources and stores. Each
application still has to put them together, and that assembly is several
hundred lines that every application writes again:

- **Configuration.** Issuer, client ID and secret, public URL, allowed
  origins, audience, accepted clients and the DPoP key, read from the
  environment and checked with messages that name the setting.
- **The DPoP key.** Parsing a PEM P-256 key, refusing anything else, and
  telling the operator how to make one. An application that forgets the key
  still starts, generates a key per process, and signs everyone out on every
  deploy.
- **Membership filtering.** Keeping only the organizations where the person
  holds one of this application's roles.
- **Request authentication.** Running `BearerMiddleware` through a recorded
  response to read its answer. Some applications also repeat checks that
  `relyingparty` already makes: the origin and content type of cookie
  requests that change state, and whether the principal is active.
- **Calling SystemAuth for the person.** Finding the session's token and
  sending it with the v0.25 transport.

Because each copy is written by hand, the copies drift. Applications differ
in whether they require the DPoP key, whether they check the origin of
cookie writes, whether insecure cookies follow the public URL, and which
`WWW-Authenticate` challenge they send. Each difference is a place where one application is weaker than the
others, and every SystemForge release that changes the relying party has to
be applied to each copy separately.

Some applications go further and issue their own tokens after sign-in
(`session/jwt`, `session/bff`). They then keep their own refresh tokens and
session store, cannot use the `orgs` claim, and do not get DPoP binding or
access-change revocation.

## Goals

1. **One package that assembles the relying party** for an application:
   from a configuration and a few options to a mounted `/bff/*` handler and
   one way to authenticate requests.
2. **Safe defaults that are the same everywhere.**
   - The DPoP key is required.
   - Cookie writes are checked for origin and content type, and refused
     with a 403 rather than a 401.
   - Cookies are insecure only for a loopback public URL.
3. **Configuration errors that name the setting** in a form a host can
   relabel. For example, `PublicURL (APP_PUBLIC_URL)` becomes
   `app.public_url` in the host's configuration file.
4. **Hooks for what differs between applications.** The hooks cover:
   - the application's key in the role vocabulary, and which roles it knows;
   - where memberships come from;
   - extra authenticators chained after the session and token, such as
     AAuth for agents;
   - the error each application returns.
5. **Calls to SystemAuth for the person,** such as the managed-principal API,
   in one line, with DPoP proofs.
6. **A shared Postgres principal store** with systemforge's own table,
   `sf_rp_principals`, for applications that keep principals in a plain
   table. They move their rows into it once and stop maintaining a copy.
7. **No behavior change for SystemAuth.**

## Non-Goals

- **Replacing `identity/relyingparty`.** The new package uses it. An
  application that needs something unusual can still assemble the parts
  itself.
- **Mapping to an application's principal type.** The package returns
  `requestprincipal.RequestPrincipal` and
  `relyingparty.AuthenticatedPrincipal`. Each application keeps its own
  conversion to its own type.
- **Removing `session/jwt` and `session/bff`.** `multiapp` uses them, and so
  do applications that issue their own tokens. Their documentation will say
  that an application signing in through SystemAuth should use the new
  package instead.
- **Deciding ADR-016.** API keys stay available as an option, as they are in
  `BearerConfig` today, so applications can migrate in steps. Service
  accounts, which replace them for automation, are `INIT-SYSTEMFORGE-010`.
  This package accepts their tokens with one option.
- **An in-process transport to an embedded SystemAuth.** A host that embeds
  SystemAuth can already pass its own `HTTPClient`.
- **Frontend changes.** The `/bff/*` contract is unchanged, so
  `@plexusone/auth` keeps working.

## Users

| User | Needs |
| --- | --- |
| Application developer | A few lines to add SystemAuth sign-in, sessions and API authentication that match every other SystemForge application |
| Host developer | Configuration errors that point at the host's own setting names; the same DPoP key file convention for every application it composes |
| Operator | A clear refusal to start without a DPoP key, with the command that makes one |
| Security reviewer | One implementation of origin checks, DPoP, inactive principals and challenges to review, instead of one per application |

## Success Criteria

- An application's authentication setup is under 60 lines, not counting its
  principal type conversion.
- Three applications with different principal stores and role vocabularies
  adopt the package without forking it.
- An application that calls SystemAuth's managed-principal API for a signed-in
  person does it with the package's transport, and the call succeeds with
  DPoP-bound tokens.
- An end-to-end test against an embedded SystemAuth covers sign-in, a restart
  that keeps the session, refusal of a bearer token, and a call to the
  managed-principal API.

## Open Questions

None. API keys are an opt-in marked deprecated from the start, kept only so
an application that has them can adopt the package before replacing them.
Command-line tools sign in with `identity/publicclient`, and automation
without a person uses service accounts (`INIT-SYSTEMFORGE-010`).
