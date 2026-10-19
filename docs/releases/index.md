# Releases

Release notes, one file per version, newest first. The
[changelog](changelog.md) is generated from `CHANGELOG.json` and lists every
change with its commit.

The latest release, [v0.17.0](v0.17.0.md), lets relying-party applications
manage managed principals through an API on SystemAuth and a Go client,
requires consent before anyone becomes a manager, and refuses contract
operations until an application is federated. The last two are breaking;
read its upgrade notes first.

The previous release, [v0.16.0](v0.16.0.md), added reconnecting, bindings and
per-connection grants to the connections API and renamed the connection
library from connectionforge to connectforge. The rename is breaking for
deployments that enabled connections in v0.15.0.

The release before it, [v0.15.0](v0.15.0.md), added key management through
keyforge, connections to external services, invite-only sign-up with a
waitlist, an app catalog for product switchers, and the `orgs` claim with
per-application roles in embedded SystemAuth.

Earlier, [v0.14.0](v0.14.0.md), made Principal the sole identity
root, added managed principals and a security pass over the APIs, and
completed the organization model. It is a breaking release with migrations
0002 to 0009; read its upgrade notes first.

| Version | Release date |
|---|---|
| [v0.17.0](v0.17.0.md) | 2026-10-18 |
| [v0.16.0](v0.16.0.md) | 2026-10-14 |
| [v0.15.0](v0.15.0.md) | 2026-10-13 |
| [v0.14.0](v0.14.0.md) | 2026-10-11 |
| [v0.13.0](v0.13.0.md) | 2026-10-06 |
| [v0.12.0](v0.12.0.md) | 2026-10-06 |
| [v0.11.0](v0.11.0.md) | 2026-10-02 |
| [v0.10.0](v0.10.0.md) | 2026-09-06 |
| [v0.9.0](v0.9.0.md) | 2026-08-23 |
| [v0.8.0](v0.8.0.md) | 2026-06-21 |
| [v0.7.0](v0.7.0.md) | 2026-05-10 |
| [v0.6.0](v0.6.0.md) | 2026-04-12 |
| [v0.5.0](v0.5.0.md) | 2026-04-05 |
| [v0.4.0](v0.4.0.md) | 2026-03-23 |
| [v0.3.0](v0.3.0.md) | 2026-03-14 |
| [v0.2.0](v0.2.0.md) | 2026-03-08 |
| [v0.1.0](v0.1.0.md) | 2026-02-28 |
