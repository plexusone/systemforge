# Security Policy

SystemForge handles identity, sessions, tokens and authorization for the
applications that embed it, so we treat security reports as our highest
priority.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a
vulnerability**.

Please **do not** open a public issue, pull request or discussion for a
suspected vulnerability. A public report puts every application that embeds
SystemForge at risk before a fix is available.

## What to include

A useful report lets us reproduce the problem without guessing. Please
include:

- the affected package or packages (for example `systemauth`, `session/bff`,
  `identity/oauth`) and the SystemForge version or commit;
- the configuration that matters (for example whether DPoP, a shared replay
  cache or a token HMAC secret is configured);
- the steps or a minimal program that reproduces the issue;
- what an attacker gains: the impact, and the preconditions they need;
- any suggested fix or mitigation you already have.

Do not include real user data, production tokens or secrets. If a proof of
concept needs credentials, use throwaway test values.

## Response targets

| Step | Target |
|------|--------|
| Acknowledge the report | Within 3 business days |
| Initial assessment (validity and severity) | Within 7 days |
| Fix, critical severity | Within 14 days |
| Fix, high severity | Within 30 days |
| Fix, medium or low severity | The next minor release |

Severity follows CVSS. We keep you informed while we work on the fix and
tell you if a target will be missed and why.

## Supported versions

| Version | Security fixes |
|---------|----------------|
| Latest minor release | Yes |
| Previous minor release | For 60 days after the latest minor is released |
| Older releases | No |

SystemForge is pre-1.0: a minor release may include breaking changes. Each
release that breaks an API or a configuration ships with an upgrade guide in
its [release notes](docs/releases/index.md), so moving to a supported
version is a documented step rather than a guess.

## Disclosure

1. The fix ships in a release (a patch release of each supported minor).
2. We then publish a GitHub security advisory that names the affected
   module, packages and versions, so `govulncheck` reports it to anyone
   still calling the affected code.
3. The release notes describe the fix and what operators need to do.

We ask reporters to keep a vulnerability private until the advisory is
published.

## Credit

We credit reporters in the advisory and the release notes, by the name or
handle they choose. Tell us in your report if you prefer to remain anonymous.

## Operating SystemForge securely

Before going live with an application that embeds SystemAuth, walk the
[production checklist](docs/security/production-checklist.md).

The [threat model](docs/security/threat-model.md) describes the assets,
actors and trust boundaries SystemForge is designed around, the controls
that address each threat, and the residual risks an operator accepts. A
report that shows a gap between the model and the code is a valid
vulnerability report.
