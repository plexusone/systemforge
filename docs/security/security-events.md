# Security Events

SystemForge records security-relevant actions as structured events through
`contract/audit`: every event is an `audit.Event` handed to an
`audit.Emitter`. The events answer the first questions of an incident: who
signed in or was refused, which client was refused a token and why, whether
a token was replayed, what was revoked, who changed whose role, and what the
server was running with.

No event carries a token, an authorization code, a PKCE verifier, a client
secret, a key, a DPoP proof or a session cookie. A test runs the sign-in,
token and sign-out flows with logging at debug level and fails if any of
them appears in a log record or an event.

## Recording events

| Component | Option |
|-----------|--------|
| `identity/systemauth` | `systemauth.WithAuditEmitter(e)` |
| `identity/systemauthsvc` | `Options.AuditEmitter`; it is passed to SystemAuth and to the services the package builds |
| `identity/organization` | `organization.WithAuditEmitter(e)` |
| `identity/principal` | `principal.WithAuditEmitter(e)` |
| `identity/serviceaccount` | `serviceaccount.Config.Audit` |

Without an emitter, events are discarded. `audit.NewLogEmitter(logger)`
writes each event as one log record with the message `security event`, at
warning level when its outcome is `failure` and info level otherwise. The
`systemauth` command uses it, so its log carries the security events.
An application with an audit store wraps the store's `Record` in an
`Emitter`.

## Common fields

| Field | Content |
|-------|---------|
| `event_type` | The event type listed below |
| `action` | What was done |
| `outcome` | `success` or `failure` |
| `actor` | Who acted: a principal (`id`), an OAuth client (`type: application`, `identifier`: client ID), or SystemAuth itself (`type: service`) |
| `resource` | What the action applied to |
| `context.request_id` | The ID of the HTTP request (chi's `middleware.RequestID`) |
| `context.client_ip` | The client address (SystemAuth's events) |
| `context.user_agent` | The client's `User-Agent` (SystemAuth's events) |
| `context.tenant_id` | The organization (membership events) |
| `details` | Event-specific fields below |

The client address comes from SystemAuth's client-address rule
(`client_address`, see [Client Addresses and Rate Limiting](../guides/rate-limiting.md#the-client-address)),
the same one rate limits use, so behind a trusted proxy it is the visitor's
address. For a refused token request the `client_id` is the one the request
names; the client may not have been authenticated.

## SystemAuth events

| Event type | Action | Outcome | Details |
|------------|--------|---------|---------|
| `systemauth.sign_in` | `sign_in` | `success` | `method` (social provider, or `login_token`), `client_id` (login token) |
| `systemauth.sign_in` | `sign_in` | `failure` | `method`, `client_id`, `reason` |
| `systemauth.sign_out` | `sign_out` | `success` | `method`, `tokens_revoked` |
| `systemauth.token.refused` | `issue_token` | `failure` | `grant_type`, `client_id`, `reason`, `error` (RFC 6749 error code) |
| `systemauth.refresh_token.reuse` | `redeem_refresh_token` | `failure` | `grant_type`, `client_id`, `family_revoked` |
| `systemauth.authorization_code.reuse` | `redeem_authorization_code` | `failure` | `grant_type`, `client_id`, `family_revoked` |
| `systemauth.token.revoked` | `revoke` | `success` or `failure` | `client_id`, `token_type_hint`, `error` |
| `systemauth.token_family.revoked` | `revoke` | `success` | `reason`, `subject`, `client_id`; `resource.identifier` is the family's request ID |
| `systemauth.email_verification.sent` | `send_verification` | `success` | `purpose` (`verify_email` or `email_change`), `sent` (false when a send limit suppressed the message or delivery failed); the address is never recorded |
| `systemauth.email.verified` | `verify_email` | `success` | `purpose`, `method` (the pending sign-in's provider) |
| `systemauth.signing_key.loaded` | `load` | `success` | `key_id`, `verification_key_ids`, `ephemeral` |
| `systemauth.production.waiver` | `waive` | `success` | `check`, `setting`, `risk` (from `systemauthsvc`, at startup) |

A signing-key rotation shows at the next start as a new `key_id`, with the
previous key among the `verification_key_ids`.

### Sign-in refusal reasons

| Reason | Meaning |
|--------|---------|
| `upstream_denied` | The social provider returned an error |
| `invalid_state` | The login state was missing, did not match the browser, was used or expired |
| `missing_code` | The provider's callback had no code |
| `upstream_exchange_failed`, `upstream_profile_failed` | The provider's token or profile request failed |
| `email_not_verified`, `email_conflict` | The account's email is not verified, or belongs to another account |
| `principal_inactive` | The account is disabled |
| `not_invited` | Sign-up is by invitation and there was none |
| `verification_invalid` | An email verification link was invalid, expired, replaced, already used or opened without the browser that asked for it |
| `login_token_rejected` | A managed principal's login token was refused |
| `server_error` | SystemAuth failed |

### Token refusal reasons

| Reason | Meaning |
|--------|---------|
| `unreadable_request` | The body could not be read |
| `dpop_proof` | The DPoP proof was refused, or a code bound to a key had none |
| `request_invalid` | Fosite refused the request: client authentication, grant, code, refresh token, PKCE or scope |
| `production_policy` | A grant or client the production policy refuses |
| `dpop_binding` | The tokens could not be bound to the proof's key, or a bound grant had no proof by its key |
| `principal_inactive` | The principal is no longer active; its family is revoked |
| `managed_principal_refused` | The client does not allow managed principals |
| `token_family_lifetime` | The refresh-token family outlived its absolute lifetime; it is revoked |
| `response_failed` | Issuing the tokens failed, or a concurrent exchange used the code |
| `server_error` | SystemAuth failed |

### Token family revocation reasons

`principal_inactive` and `token_family_lifetime`, as above. Fosite revokes
the family itself on refresh-token reuse and code replay; those are recorded
as their own events with `family_revoked: true`.

## Identity service events

| Event type | Actions | Resource | Details |
|------------|---------|----------|---------|
| `organization.membership` | `added`, `updated`, `removed`, `ownership_transferred` | `membership`, the principal's ID | `organization_id`, `principal_id`, `role`; `old_role`, `was_active`, `active` for `updated`; `previous_owner_id`, `previous_owner_role` for `ownership_transferred` |
| `principal.platform_admin` | `granted`, `revoked` | `principal` | none |
| `service_account` | `created`, `disabled`, `enabled`, `deleted`, `key_added`, `key_revoked`, `role_granted`, `role_removed` | `service_account` | `identifier`, `organization_id`; `key_id`, `algorithm`, `expires_at`, `reason` for keys; `application`, `role` for roles |

The actor of membership and platform-administration events is the
request's principal (`requestprincipal`) when the change is made in an
authenticated request; the actor of service-account events is the operator
the call names.

## Error logging

SystemAuth logs a refused OAuth request with an `error` group holding the
RFC 6749 `code`, `description`, `hint` and `status`, never the error value
itself, so neither the text nor the JSON format prints a stack trace. The
wrapped cause and Fosite's debug text are added as `error.cause` and
`error.debug` when the logger is enabled at debug level, and the cause for
server errors at any level.
