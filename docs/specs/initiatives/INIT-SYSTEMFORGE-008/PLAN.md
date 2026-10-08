# PLAN — Retire Legacy User — Principal as the Sole Identity Root

**Initiative:** `INIT-SYSTEMFORGE-008`

## Entry Gate

- ADR-004 accepted.
- Confirmed that no consumer application reads `sf_users` or the legacy
  tables directly (downstream products link through `relyingparty` and
  `sf_principal_id`).
- Current release is v0.13.0; the next tag is reserved as breaking v0.14.0.

## Build Order

### Phase 1 — SystemAuth on Principal

Land the bootstrap and OAuth-app ownership change first so the client owner
is valid before the storage layer stops looking at `sf_users`. Then move the
storage methods, remove `legacyUserID`, and re-express federation sync as
external identities. Exit: password login, social login, and federation sync
all resolve to the same `Principal` + `Human`; the two legacy test files pass
against the new storage.

### Phase 2 — SCIM and Service Accounts

Expand SCIM tests to pin wire behavior, then rewrite the store on
`Principal`/`Human`/`PrincipalMembership`. In parallel, settle the
service-account question (TRD §5) so the removal list is fixed. Exit: SCIM
suite green on the new store; service-account decision recorded in the
removal RMI.

### Phase 3 — Removal and Release

Delete the legacy schemas, regenerate Ent, add migration `0002`, rewrite the
identity docs and README bullets, fix `rls/testing.go`, extend the CI grep
gate, update `CHANGELOG.json`, and tag v0.14.0 after CI passes. Record the
release in visionstudio at the same moment. Exit: the success criteria in the
PRD hold.

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Removing schemas before every caller moved | Phase 3 cannot start until Phases 1 and 2 are complete; Ent regeneration turns stragglers into compile errors |
| SCIM regressions | Tests first, rewrite second |
| Service-account scope grows the initiative | Time-box the decision in Phase 2; repoint the edge and defer table removal if needed |

## Follow-On

- INIT-SYSTEMFORGE-007: optional `Human.email` under application
  configuration, QR login credential type, guardian/educator relationships.
- Enforce case-insensitive email uniqueness in the database with a
  PostgreSQL `lower(email)` unique index on `sf_humans`, created by the
  migrate step on PostgreSQL. Writes already check case-insensitively
  inside their transaction, but only an index closes the race between
  concurrent creates. It needs the dialect passed into the migrate step.
- Fix `identity/oauth.NewProvider`, which panics on construction because
  its `Storage` does not implement `fosite.Storage`
  (`ClientAssertionJWTValid` is missing). This predates the initiative;
  the documentation now points to SystemAuth instead of this package.
- Retire or realign the legacy-shaped mixins in `identity/ent/mixin`
  (`UserBase`, `MembershipBase`, `OAuthAccountMixin`, `RefreshTokenMixin`,
  and the `HumanMixin` fields that `sf_humans` does not have), so
  applications cannot compose a diverging user model.
- Decide whether `organization.Service.ListMembers` and `ListMemberships`
  should exclude inactive memberships, as the SCIM store now does.
- Rename the Core-era default BFF session cookie `cf_session`, with a
  migration note, since renaming it signs existing sessions out.
- Implement the RFC 7523 JWT-bearer grant on `ServicePrincipal` plus
  `keypair` credentials. It was documented but never wired into Fosite;
  the service-account tables it described are removed by this initiative.
