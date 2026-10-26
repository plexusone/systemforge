# Browser Cookies

Every cookie SystemForge sets is `HttpOnly`, has `Path=/` and no `Domain`
attribute, so it is host-only: a sibling subdomain can neither read nor
overwrite it, and each application keeps its own cookies. In production
every cookie is `Secure` and carries the `__Host-` prefix, which makes
browsers enforce those attributes.

| Component | Cookie | Development name | SameSite | Development switch |
|-----------|--------|------------------|----------|--------------------|
| SystemAuth login session | `__Host-sf_login` | `sf_login` | Lax | `social_login.insecure_cookies` |
| SystemAuth upstream login state | `__Host-sf_oauth_state` | `sf_oauth_state` | Lax | `social_login.insecure_cookies` |
| SystemAuth sign-up age question | `__Host-sf_signup_age`, `__Host-sf_signup_age_ok`, `__Host-sf_signup_age_refused` | same without `__Host-` | Lax | `social_login.insecure_cookies` |
| Relying-party BFF session | `__Host-sf_rp_session` | `sf_rp_session` | Lax | `BFFConfig.InsecureCookies` |
| Relying-party BFF login state | `__Host-sf_rp_state` | `sf_rp_state` | Lax | `BFFConfig.InsecureCookies` |
| `session/bff` session | `__Host-sf_session` (configurable) | `sf_session` | Strict (configurable) | `CookieConfig.AllowInsecure` |
| `oauthclient` state | `__Host-sf_oauth_client_state` (configurable) | `sf_oauth_client_state` | Lax (fixed) | `StateManager.AllowInsecure` |

SameSite is Lax where the cookie must accompany a top-level redirect back
from another site (an upstream provider or SystemAuth); Strict would drop it
on that redirect. The `session/bff` session cookie is only read on
same-site API calls, so it defaults to Strict.

## Development over plain HTTP

Browsers refuse `Secure` cookies over plain HTTP, so each component has a
switch that drops `Secure` and the `__Host-` prefix for local development.
Never set it in production. Each component logs a warning once at startup
when its switch is on, so an insecure setting that reaches a deployed
environment shows up in the logs:

- SystemAuth social login, when `insecure_cookies` is set (the `systemauth`
  server additionally refuses it outside `--dev`).
- `relyingparty.NewBFF`, when `InsecureCookies` is set.
- `bff.NewHandler`, when `AllowInsecure` leaves the session cookie without
  `Secure`.
- `oauthclient.NewStateManagerInsecure`.

## Refused configurations

- `session/bff`: `CookieConfig` has no `Domain` field; the session cookie is
  always host-only. `NewHandler` refuses a `__Host-` name with a `Path`
  other than `/` or without `Secure`, and a `__Secure-` name without
  `Secure`.
- `oauthclient`: `StateManager` refuses SameSite Strict or None, and a
  `__Host-` or `__Secure-` name without `Secure`. A zero-value or hand-built
  `StateManager` writes the secure default cookie.
