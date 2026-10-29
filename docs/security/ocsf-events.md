# OCSF Security Events

`contract/audit/ocsfaudit` writes SystemForge's [security events](security-events.md)
as [OCSF](https://schema.ocsf.io/) events, one JSON object per line, for a
security data lake or SIEM that ingests OCSF. Events follow OCSF schema
`1.10.0-dev`, the development version of OCSF 1.10, which they carry in
`metadata.version`; check that a destination accepts it. They use the
generated types and embedded schema of `github.com/grokify/ocsf-schema-go`
v0.2.0, and a test validates the output of every event type against that
schema.

## Wiring

`ocsfaudit.New` returns an `audit.Emitter`. Pass it wherever an emitter is
taken, such as `systemauthsvc.Options.AuditEmitter`. To keep the log of
security events as well, combine both with `audit.NewMultiEmitter`, which
hands every event to each emitter in turn:

```go
f, err := os.OpenFile("/var/log/systemauth/security.ocsf.jsonl",
    os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
if err != nil {
    return err
}
defer f.Close()

ocsf := ocsfaudit.New(f, ocsfaudit.Options{
    Deployment: "prod-eu",
    Logger:     logger,
})
defer ocsf.Close() // runs before f.Close: drains the queue and syncs the file

opts.AuditEmitter = audit.NewMultiEmitter(audit.NewLogEmitter(logger), ocsf)
```

| Option | Default | Use |
|--------|---------|-----|
| `ProductName` | `SystemForge` | `metadata.product.name` |
| `ProductVersion` | the SystemForge module version in the binary's build information | `metadata.product.version` |
| `VendorName` | `PlexusOne` | `metadata.product.vendor_name` |
| `Deployment` | none | `metadata.reporter.name`, to tell deployments apart |
| `BufferSize` | 1024 | Events queued before new ones are dropped |
| `Logger` | `slog.Default()` | Write failures and the counts of dropped and unencodable events, logged from the emitter's own goroutines |

## Delivery

`Emit` never blocks, never logs and never fails the request: it maps the
event, queues the line and returns. One goroutine writes the queue in
order, one `Write` per line, so an append-mode file gets whole lines. The
logger is called only from the emitter's own goroutines, so a slow or
stuck log destination cannot hold up a request.

- **Queue full.** The event is dropped and counted; `Dropped()` returns the
  count. A reporter goroutine logs the number dropped at warning level
  once a minute when there were drops, and once more on `Close`. An event
  that cannot be encoded is counted the same way (`EncodeFailures()`).
- **Write failure.** Logged at error level at most once a minute, with the
  number of failures since; `WriteFailures()` counts them. A `Write` that
  reports fewer bytes than the line without an error counts as a failure
  (`io.ErrShortWrite`).
- **Torn lines.** When a `Write` fails part-way, as on a full disk, it may
  leave a partial line. The next line then starts with a newline, so the
  partial line is the only one lost and every following line is whole
  JSON.
- **Flushing.** A writer with `Flush` (a `*bufio.Writer`) is flushed
  whenever the queue empties.
- **Close.** Stops accepting events, writes the queue, flushes, and calls
  `Sync` on a writer that has it (an `*os.File`). A `Sync` refused because
  the file cannot be synced, such as a pipe or a terminal, is not an error.
  It does not close the writer. A second `Close` returns the first one's
  result; an event emitted after `Close` is dropped and counted.

The package does not rotate files. Rotate by renaming: logrotate's default
`create` mode, with a writer that reopens its file on `SIGHUP` from
`postrotate`, loses nothing. Avoid `copytruncate`: an event written after
logrotate copies the file and before it truncates it is in neither file,
and the emitter cannot see or count that loss.

## Event classes

`metadata.event_code` keeps the SystemForge event type, so events can be
selected by it as well as by OCSF class.

| Event type | OCSF class (`class_uid`) | Activity | Severity |
|------------|--------------------------|----------|----------|
| `systemauth.sign_in` | Authentication (3002) | Logon | Informational; Low on failure |
| `systemauth.sign_out` | Authentication (3002) | Logoff | Informational |
| `systemauth.token.refused` | Authentication (3002) | Logon, protocol OAuth 2.0 | Low |
| `systemauth.refresh_token.reuse` | Authentication (3002) | Logon, protocol OAuth 2.0 | High |
| `systemauth.authorization_code.reuse` | Authentication (3002) | Logon, protocol OAuth 2.0 | High |
| `systemauth.token.revoked` | Authentication (3002) | Logoff, protocol OAuth 2.0 | Informational; Low on failure |
| `systemauth.token_family.revoked` | Authentication (3002) | Logoff, protocol OAuth 2.0 | Informational |
| `systemauth.email_verification.sent`, `systemauth.email.verified` | Authentication (3002) for purpose `verify_email`; User Management (3007) for `email_change` | Preauth; Update | Informational |
| `systemauth.email_change.requested`, `.cancelled`, `systemauth.email.changed` | User Management (3007) | Update | Informational |
| `systemauth.signing_key.loaded` | Application Lifecycle (6002) | Start | Informational |
| `systemauth.production.waiver` | Application Lifecycle (6002) | Start | Medium |
| `organization.membership` | Group Management (3006) | Add User (`added`), Remove User (`removed`), Update (`updated`, `ownership_transferred`) | Informational; Medium for `ownership_transferred` |
| `principal.platform_admin` | User Management (3007) | Assign Privileges (`granted`), Remove Privileges (`revoked`) | High when granted |
| `service_account` | User Management (3007) | Create, Disable, Enable, Delete, Add/Remove Programmatic Credentials (keys), Assign/Remove Roles | Informational |
| `keys` | Entity Management (3004) | Create, Activate, Deactivate (retired), Delete (destroyed, shredded), Read (admin read, guard), Update (others) | High for `key.compromised`, `dek.compromised`; Medium for destroy, shred, `wrap.failed`, `guard.denied`, `job.failed`, `backup.stale` |
| `connections` | Entity Management (3004) | Create, Read (validated, access denied), Deactivate (disconnected, credential revoked), Delete, Update (others) | Medium for `access.denied` |
| `scim_token.issued`, `.rotated`, `.revoked` | Entity Management (3004) | Create, Update, Deactivate | Informational |
| `scim_token.authentication_failed` | Authentication (3002) | Logon, failure | Medium |
| `signup_code.*`, `signup_invite.*`, `signup_waitlist.invited`, `signup_allowance.set` | Entity Management (3004) | Create, Update (redeemed, allowance), Deactivate (revoked) | Informational |
| `managed_principal.created`, `deleted`, `released`, `email_attached`, `email_verified`, `claim_issued`, `claim_redeemed`, `manager_added`, `manager_removed` | User Management (3007) | Create, Delete, Update | Informational; Low for `deleted` |
| `managed_principal.login_token_issued`, `login_token_revoked` | User Management (3007) | Add / Remove Programmatic Credentials | Informational |
| `managed_principal.manager_invited`, `manager_invite_accepted`, `manager_invite_declined`, `manager_invite_revoked` | Entity Management (3004) | Create, Update, Deactivate | Informational |
| `managed_principal.session_revoked`, `all_revoked` | Authentication (3002) | Logoff | Informational |
| Any other event type | Base Event (0) | Other, named by the action | Informational; Low on failure |

A failure outcome raises Informational to Low; High sets `is_alert`.

Notes on the choices:

- **Token requests** are authentications of the client to the token
  endpoint, so a refused request and a replay are failed Logons with
  protocol OAuth 2.0. OCSF's ticket activities are Kerberos-specific and
  are not used. Revoking a token or a token family ends access: Logoff.
- **Verifying a sign-in's email** is a step before authentication
  (Preauth); verifying or changing an account's email is an update of the
  account.
- **The startup events** (signing key, production waivers) describe the
  application starting with a configuration, so they are Application
  Lifecycle, Start.
- **OCSF's deprecated attributes and classes** are not used: Account Change
  and User Access are replaced by User Management and Group Management,
  `actor.app_uid` by `actor.application.uid`.
- **Unknown event types** become a Base Event, the class OCSF defines for
  events without a better one, so no event is dropped. Their details are
  not copied (there is no allowlist for them); the resource is kept by type
  and ID in `unmapped`.

## Common attributes

| Attribute | Content |
|-----------|---------|
| `time` | The event time, in milliseconds |
| `metadata.uid` | The event ID, or a new UUID when the event has none |
| `metadata.correlation_uid` | The request ID (`context.request_id`) |
| `metadata.event_code` | The SystemForge event type |
| `metadata.tenant_uid` | The organization: `context.tenant_id`, or the event's `organization_id` |
| `metadata.product` | `ProductName`, `VendorName`, `ProductVersion` |
| `metadata.reporter.name` | `Deployment` |
| `metadata.version` | The OCSF schema version |
| `actor.user.uid`, `.type_id` | The acting principal's ID and type |
| `actor.application` | The OAuth client (`uid`: client ID), or the SystemForge component (`name`) |
| `user.uid` | The principal the event is about (Authentication, User Management) |
| `src_endpoint.ip` | The client address |
| `http_request.user_agent` | The client's `User-Agent`, sanitized: left out when it holds an email address or a credential-like value, otherwise cut to 512 bytes |
| `status_id`, `status` | `success` → Success, `failure` → Failure |
| `status_detail` | SystemForge's reason code (sign-in, token and SCIM refusals, revocations) |
| `status_code` | The RFC 6749 error code of a refused token request |
| `severity_id`, `severity` | As in the table above |
| `unmapped` | The event's allowlisted details not mapped to an attribute, such as `grant_type`, `role`, `family_revoked` |

The deployment goes in `metadata.reporter.name` because the reporter is
the entity that first reported the event: a lake holding several
deployments' events filters on it, while `metadata.product` stays the
product. The organization goes in `metadata.tenant_uid`, the attribute
OCSF gives the tenant.

A refused sign-in, or a refused token request that is not
`client_credentials`, has no known principal; its `user` is
`{"name": "unknown", "type_id": 0}` because the class requires one. For a
`client_credentials` request the client is the user (`type_id` 4, Service).

## What is never written

Only IDs and addresses identify people.

- No name, email address, token, token prefix, authorization or login
  code, DPoP proof, assertion, secret or request body appears in any
  attribute, `unmapped` and `message` included.
- `actor.identifier` and `resource.identifier` are left out, since they may
  hold email addresses (sign-up invites, key operators) or token prefixes
  (SCIM tokens). The exceptions name no person and no secret: an OAuth
  client's ID, a SystemForge component's name and a key's ID.
- `context.session_id` is left out, as in the log: it may hold a session
  token. A revoked managed-principal session
  (`managed_principal.session_revoked`) is named in `session.uid` by its
  record ID, a UUID that is no credential; no session token appears.
- The `User-Agent` is sent by the client, so it can carry anything. It is
  left out when it holds an email address or a credential-like run of
  token characters (`audit.SanitizeUserAgent`); the log emitter applies
  the same rule.
- Details are copied only from an allowlist per event type, and a value is
  copied only when it has the expected shape: a code (letters, digits and
  `_ . : / + = -`, no spaces, no `@`), a UUID, a boolean, an integer or a
  time. Free text, such as a signup code's label, a production waiver's
  risk description or a key operation's reason in words, is left out.
- Email events never carry the address.

The tests that run SystemAuth's sign-in, token, revocation, email
verification and email change flows check that none of the secrets they
handle appear in this emitter's output.
