# ADR-010: Real-Time Invalidation of Access on Membership Change

**Status:** Accepted
**Deciders:** @grokify
**Relates to:** ADR-007 (memberships and entitlements as claims; this ADR
amends its decision 9), ADR-002 (relying parties), ADR-008 (collaborators,
whose grants change the same way).
**Updates:** `docs/design/architecture/organizations.md` (freshness of
claims), `docs/design/architecture/authorization.md` (revocation cache).

## Context

ADR-007 puts a principal's organizations and application roles into the
access token as claims. A relying party verifies the token's signature and
reads the claims; it does not ask SystemAuth anything per request. That is
what makes claims cheap, and it has a cost: a change to the principal's
access is not seen until the token expires and the client refreshes.

Removing someone from an organization at 10:00 leaves a token issued at
09:58 with a fifteen-minute lifetime valid until 10:13. ADR-007 bounds the
window with short lifetimes and revokes the refresh token at removal, so the
next refresh is refused, but it cannot close the window. For routine
offboarding that is tolerable. For a contractor cut off during a dispute, a
compromised account, or an agent whose mission was revoked, it is not.

The alternatives:

- **Opaque tokens checked by introspection on every request.** Immediate,
  but every request to every product becomes a round-trip to SystemAuth.
  It does not scale with the suite, and it reintroduces the network hop the
  claims model removed.
- **Even shorter lifetimes.** Shrinks the window; never closes it.
- **A revocation signal with a small cache.** SystemAuth announces access
  changes; relying parties remember them only for as long as an affected
  token could still exist. Per-request cost is a map lookup, and the memory
  is bounded by the number of changes within one token lifetime.

The modular monolith (pbhq-cloud ADR-001) makes the signal almost free for
the suite: SystemAuth and the products share a process, so the announcement
is a function call.

## Decision

1. **Access tokens stay self-contained JWTs with short lifetimes.** The
   default lifetime is 10 minutes, configurable per deployment up to 15.
   Lifetime is the fallback bound; it is not the mechanism.
2. **SystemAuth records and announces every access change.** An access
   change is any event after which a principal's existing tokens may claim
   more than the principal now has:
   - removal from an organization, or a change of organization role;
   - change or removal of an application role (ADR-007), or of a resource
     grant that reduces access (ADR-008);
   - deactivation of the principal, or revocation of its sessions;
   - a managed principal's manager revoking its sessions (ADR-005).

   Each change is stored as `(principal_id, organization_id or null,
   changed_at, reason)` in `sf_access_changes`, and announced.
3. **Relying parties keep a revocation cache keyed by principal.** On an
   announcement they store `principal_id → changed_at` (per organization
   when the change is organization-scoped). On every request they accept a
   token only if its `iat` is at or after `changed_at` plus a clock-skew
   margin for its principal (and organization); a token stamped within the
   margin is treated as issued before the change. Otherwise they answer 401
   with the standard "token expired" error, which makes the client refresh.
   Entries are dropped once `changed_at` plus the maximum access-token
   lifetime plus the margin has passed: after that, no token issued before
   the change can be accepted by any verifier, however its clock drifts.
   The margin defaults to 30 seconds and is configurable; 15 seconds is the
   floor, enough where clocks are NTP-disciplined, and the margin is moot
   in-process, where both timestamps come from one clock. The cache is
   therefore bounded by the number of changes within one lifetime.
4. **The cache is shared memory in the monolith; delivery exists only at
   process boundaries.**
   - **Same process:** in a modular monolith (pbhq-cloud) SystemAuth and
     the relying parties share one cache instance. SystemAuth writes to it
     in the transaction that records the change, and every product reads
     it on each request. There is no delivery and no delay; the check is a
     lookup in the same memory.
   - **Replicas of the same monolith:** instances behind a load balancer
     share the database, not memory. Each instance polls
     `sf_access_changes` for rows newer than its last read, every second
     or two: one indexed query per instance per interval, independent of
     request volume. The change is visible on every replica within the
     polling interval.
   - **Separate deployments:** a relying party in another process receives
     a signed event, an OIDC Back-Channel Logout token carrying an
     `access_change` event with the same fields, at a registered endpoint.
     Delivery is retried, and failures are logged against the client.

   The `relyingparty` package implements the cache, the poller and the
   back-channel receiver, so an application adds one line of configuration
   for whichever boundary it sits on.
5. **A refresh after a change issues new claims rather than ending the
   session.** ADR-007's decision 9 ("removals revoke refresh tokens") is
   amended: a change of role or membership does not log the person out of
   every organization; their next refresh carries the reduced claims. Only
   deactivation and explicit session revocation revoke refresh tokens.
6. **Relying parties recover a lost cache by replay.** After a restart, a
   relying party calls `GET /access-changes?since=<now − max lifetime>` and
   rebuilds the cache before serving. Until the call succeeds it treats
   every token as suspect and refreshes claims from the memberships
   endpoint on first use, so a restart never widens the window.
7. **Agent tokens are out of scope.** AAuth tokens carry their own
   revocation (cascading, keyed by `jti`); a mission revocation reaches
   resources through that path. This ADR covers SystemAuth-issued tokens.

## Consequences

- **Access changes take effect within one request** in the same process;
  within the polling interval on other replicas; within the back-channel
  delivery time for separate deployments; and within one token lifetime if
  a signal is lost, which is the bound ADR-007 already had.
- **Per-request cost is a map lookup**, and the cache holds only the
  changes of the last lifetime: tens of entries for a large deployment, not
  one per user.
- **SystemAuth gains a table, an announcement in the membership and role
  transactions, a replay endpoint, and back-channel delivery with retry.**
- **Relying parties gain the cache, the receivers and the replay call**,
  all in the `relyingparty` package. Applications that bypass it must
  implement the same check.
- **A role change no longer logs the person out.** Products must handle
  claims that shrink between requests without a new login.
- **The token lifetime is a visible setting**, not an assumption. The
  architecture pages state the default and the maximum.
