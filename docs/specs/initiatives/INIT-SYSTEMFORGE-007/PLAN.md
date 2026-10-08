# PLAN — SystemForge Learner Accounts — Optional Email, QR Login, Guardian and Educator Relationships

**Initiative:** `INIT-SYSTEMFORGE-007`

## Entry Gate

- ADR-005 accepted.
- INIT-SYSTEMFORGE-008 released (v0.14.0): one human model, `HumanPrincipal`
  DTO, legacy tables gone.
- Null-uniqueness behavior of `Human.email` confirmed on the deployment
  database.

## Build Order

### Phase 1 — Model and Invariants

Make `Human.email` optional and set the identifier rule; add the
`Application` flag and deployment setting; add `ManagerRelationship` and the
`identity/managedprincipal` service with its invariants and audit. Exit: a
managed principal can be created and managed through the service, cannot be
created without a manager or when either flag is off, and all existing suites
pass with both flags off.

### Phase 2 — Sign-in and Control

Add the `login_token` credential type with issue, verify, and revoke; the
SystemAuth exchange endpoint with identical failure responses and rate
limiting; `managed` claims and conditional `email` claims; manager listing
and revocation of tokens and sessions; the base authorization relations.
These land together because the mitigations for a reusable token are the
other items in the phase. Exit: end-to-end sign-in of a managed principal
with a token, visible to and revocable by its manager, authorized through
`authz`.

### Phase 3 — Surfaces and Release

Audit and adjust every email-assuming path; implement the `educator` →
`guardian` claim flow and the attach-email flow; write the documentation;
tag v0.15.0 after CI passes and record the release. Exit: PRD success
criteria hold.

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Shipping tokens before mitigations | Phase 2 is indivisible; no partial tag |
| Missed email assumption | Phase 3 audit item is checklist-driven from a repository-wide search; conformance suites carry no-email cases from Phase 1 |
| Blocking on INIT-006 for attach-email | Only the attach step depends on it; the claim flow and everything else do not |

## Follow-On

- First consumer integration in the learning application (its own
  initiative), including consent recording and application facet
  permissions.
- Optional device binding for `login_token` if a consumer requires stronger
  assurance than reusable tokens provide.
