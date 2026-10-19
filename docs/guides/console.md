# The Organization Console

The organization console is where people administer an organization for
every application at once: its connections to external services first, and
its members, roles and access as they join. SystemAuth serves it under
`/console` on its own host, signed in with the SystemAuth login session. The
design is [ADR-018](../design/adrs/ADR-018-organization-console.md).

## Enable the console

Add a `console` section to the SystemAuth configuration. The console signs
in with social login's session, so `social_login` must be configured too.

```yaml
social_login:
  github:
    client_id: ${SYSTEMAUTH_GITHUB_CLIENT_ID}
    client_secret: ${SYSTEMAUTH_GITHUB_CLIENT_SECRET}
console:
  web_dir: /opt/myapp/web/console
```

| Key | Meaning |
|---|---|
| `web_dir` | Directory of the console's built pages, with an `index.html`. Empty serves only the console's API |

The connections section appears when [connections](connections.md) are
enabled. Startup fails when `console` is set without `social_login`, or when
`web_dir` has no `index.html`.

## Build the pages

The pages are a static build of `@plexusone/console` from
[systemforge-web](https://github.com/plexusone/systemforge-web), built by
the host application with its own chrome and with `/console/` as the base
path. Point `web_dir` at the output. The console serves:

- each file under `web_dir`; files under `assets/` are cached as immutable,
  others revalidated;
- `index.html` for every other path under `/console/`, never cached, after
  sending a person without a session to `/login?return_to=<the page>`.

Every response carries a content security policy that allows only the
console's own scripts and connections, and refuses framing.

## API

The console's API is under `/console/api`, authenticated by the login
session. A request without one gets `401 {"error":"sign in required"}`.

| Call | Returns |
|---|---|
| `GET /console/api/v1/session` | The person's ID, their organizations (personal first, each with the person's role), and which sections are enabled |
| `GET /console/api/v1/return-to?url=` | The return address, when sign-in's redirect policy allows it, else `400` |
| `/console/api/v1/providers` and `/console/api/v1/organizations/{org}/connections/...` | The [connections API](connections.md#http-api), unchanged |

OAuth scopes do not apply to the console: it is SystemAuth's own interface
acting as the signed-in person. Every call is authorized by the person's
organization role and grants, as any caller's is, with the organization in
the path as the row-level security tenant.

**Cross-site requests are refused.** A state-changing request must be
same-origin, judged by `Sec-Fetch-Site`, or by `Origin` against the host,
using Go's `http.CrossOriginProtection`. Browsers send these headers; a
script on another site cannot make a state-changing request with the
person's session.

## Link from an application

An application links to the console instead of hosting administration pages.
A link can carry a return address, which the pages check with
`/console/api/v1/return-to` before sending the person back:

```text
https://auth.example.com/console/orgs/{org}/connections/new?provider=cloudflare&return_to=https://app.example.com/sites/new
```

`return_to` passes when it is a path on the SystemAuth host or a URL on one
of `social_login.allowed_redirect_origins`.
