# PLAN — JWT Bearer Authorization Grant — Service Principals with Keypair Credentials

**Initiative:** `INIT-SYSTEMFORGE-010`

## Entry Gate

- PRD open questions resolved (client authentication default; agent
  principals).
- INIT-SYSTEMFORGE-009 released, since the grant reuses its client-assertion
  JTI store.

## Build Order

### Phase 1 — Storage and Composition

Build the key-storage adapter with its rejection rules and scope
intersection, then register the Fosite factory behind configuration and
advertise the grant in discovery. Exit: an embedded SystemAuth issues a
token for a correctly signed assertion and rejects every PRD failure case.

### Phase 2 — Client, Documentation, Release

Add the reference client helper, rewrite the service principals page with
an end-to-end walkthrough, add release notes, and tag after CI passes.
Exit: PRD success criteria hold.

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Accepting a key for the wrong subject | Adapter enforces key ownership and self-issuance; direct tests |
| Enabling the grant by accident | Disabled by default; discovery only advertises it when enabled |

## Follow-On

- Trusted third-party issuers (workload identity federation).
- Admin endpoints for keypair registration and rotation.
- Agent principals using the grant, if the PRD question resolves that way.
