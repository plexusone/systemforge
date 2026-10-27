# Releases

Release notes, one file per version, newest first. The
[changelog](changelog.md) is generated from `CHANGELOG.json` and lists every
change with its commit.

The latest release, [v0.25.0](v0.25.0.md), lets relying parties call
SystemAuth's APIs, such as the managed-principal API with `mpclient`, with
their people's DPoP-bound session tokens (`relyingparty.Client.Transport`).
It is not breaking.

Before it, [v0.24.0](v0.24.0.md) let command-line tools and
other public clients sign people in to SystemAuth and call APIs with
DPoP-bound tokens (`identity/publicclient`), with nothing to register per
person or machine. It is not breaking.

Before it, [v0.23.0](v0.23.0.md) was a security release for
resource servers that accept AI agents: `aauthrs` accepts auth tokens only
from the server entitled to issue them, binds every signature to the resource
that receives it, and gains a revocation hook. It updates aauth-go to v0.3.0.
It is breaking for resources that accept an Access Server's auth tokens; read
its upgrade notes first.

Before it, [v0.22.0](v0.22.0.md) added invite-gated sign-up:
invite codes with use limits and cohort labels, member invites from an
allowance, attribution of every account to its invite, an invite API, and
operator commands. It is not breaking; existing databases run migration
0011.

Before it, [v0.21.0](v0.21.0.md) was a security release: tokens are
DPoP-bound by default, keys and secrets rotate keeping the current and
previous value, SCIM has built-in per-tenant tokens, revocations remove graph
access before they commit, and each multi-app application gets its own
database login. It is breaking; read its upgrade guide first.

Before it, [v0.20.0](v0.20.0.md), was also a security release:
it bound tokens to the application they were issued for and SCIM
credentials to one organization, made revocation remove access everywhere,
and made authorization checks fail closed. It is breaking; read its upgrade
notes first.

Before it, [v0.19.0](v0.19.0.md) added a minimum sign-up age:
SystemAuth asks a person's birth month and year before it creates their
account and refuses anyone younger, keeping nothing about them.

Further back, [v0.18.0](v0.18.0.md) added the organization console,
served by SystemAuth under `/console`, where organizations manage their
connections, and recorded each connection's rotation mode.

Before that, [v0.17.0](v0.17.0.md) let relying-party applications
manage managed principals through an API on SystemAuth and a Go client,
required consent before anyone becomes a manager, and refused contract
operations until an application is federated. The last two are breaking;
read its upgrade notes first.

Then [v0.16.0](v0.16.0.md) added reconnecting, bindings and
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
| [v0.25.0](v0.25.0.md) | 2026-10-27 |
| [v0.24.0](v0.24.0.md) | 2026-10-27 |
| [v0.23.0](v0.23.0.md) | 2026-10-27 |
| [v0.22.0](v0.22.0.md) | 2026-10-25 |
| [v0.21.0](v0.21.0.md) | 2026-10-25 |
| [v0.20.0](v0.20.0.md) | 2026-10-23 |
| [v0.19.0](v0.19.0.md) | 2026-10-22 |
| [v0.18.0](v0.18.0.md) | 2026-10-20 |
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
