# Security Support Policy

SystemForge fixes security issues forward. Every fix lands on `main` and
ships in the next release. There are no release branches and no backports:
the latest release is the only supported release, and getting a fix means
upgrading to it.

To report a vulnerability, see [SECURITY.md](https://github.com/plexusone/systemforge/blob/main/SECURITY.md).

## Supported versions

| Version | Security fixes |
|---------|----------------|
| Latest release | Yes |
| Older releases | No: upgrade to the latest release |

## Why fix forward

- **Speed.** Automated and AI-assisted analysis finds issues faster and in
  greater numbers than manual review. A fix forward costs one change, one
  test pass and one release, however many releases came before it.
- **Exposure after disclosure.** A published fix shows where the flaw was,
  and the time from fix to working exploit keeps shrinking. Shipping the fix
  quickly protects more users than maintaining old release lines.
- **One code path.** Release branches drift from `main`, and a fix applied
  to drifted code is where incomplete fixes and regressions come from.
- **Upgrades are cheap.** Each release documents its upgrade steps precisely
  enough for a developer, or a coding agent, to apply them directly.

Fixing forward only works when upgrading is easy, so the commitments below
keep it that way.

## What a security release contains

1. **The fix, and nothing riskier than what is already on `main`.** We keep
   `main` releasable and release often, so the distance between the latest
   release and `main` stays small when a fix is needed.
2. **No breaking change unless the fix requires one.** A fix that must change
   an API, a configuration key or a default behavior says so first in the
   release notes, with the reason.
3. **Deprecate before removing.** When a fix replaces an API, the old API
   stays for at least one release, marked `Deprecated`, and where the
   replacement is mechanical it carries a `//go:fix inline` directive so
   `go fix` rewrites callers automatically.

## Upgrade guides

Every release that changes an API, a configuration or a default ships an
upgrade guide in its [release notes](../releases/index.md). Each guide gives:

- the exact before and after code or configuration;
- the behavior that changes, and who it affects;
- how to check that the upgrade worked (a test, a log line, a health check).

Guides are written so that a coding agent can apply them without guessing.

## Advisories

After the fix is released we publish a GitHub security advisory naming the
affected module, packages and versions, and the version that fixes it.
`govulncheck` then reports the issue to anyone still calling the affected
code and points them at that version. The release notes describe the fix
and anything operators need to do.

## Stability goal

SystemForge is pre-1.0, so a minor release may include breaking changes.
Fixing forward is not a license to break APIs: the goal is to avoid breaking
changes, keep any that are unavoidable small and documented, and reach a
stable 1.0 API where fixes never require a new major version.
