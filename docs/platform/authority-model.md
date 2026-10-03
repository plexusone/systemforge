# SystemForge Authority Model

**Version**: 1.0 (Draft)
**Status**: In Development

## Overview

The SystemForge Authority Model defines a four-tier hierarchical system for governing access and administration across SaaS applications. This model supports both standalone deployments and federated multi-product platforms.

## Design Principles

### 1. Hierarchical Delegation

Authority flows downward through the hierarchy. Each tier can delegate to lower tiers but cannot exceed its own authority bounds.

### 2. Least Privilege

Each tier receives only the permissions necessary for its operational scope. Higher tiers have broader scope but not unlimited power.

### 3. Scope Isolation

Authority is scoped to specific domains. A Tenant Owner in App A has no authority in App B unless explicitly granted.

### 4. Audit Trail

All authority delegations and actions are auditable. The complete chain of authority can be traced for any operation.

## Authority Tiers

```
┌─────────────────────────────────────────────────────────┐
│              Tier 1: Federation Admin                   │
│         (Platform-wide governance - SystemAuth)        │
├─────────────────────────────────────────────────────────┤
│              Tier 2: MSP (Optional)                     │
│         (Multi-customer operations)                     │
├─────────────────────────────────────────────────────────┤
│              Tier 3: App Owner                          │
│         (Application-level configuration)               │
├─────────────────────────────────────────────────────────┤
│              Tier 4: Tenant Owner                       │
│         (Standard SaaS administration)                  │
└─────────────────────────────────────────────────────────┘
```

### Tier 1: Federation Admin

**Scope**: Platform-wide governance across all federated applications

**Available In**: Federated mode only (via SystemAuth)

#### Capabilities

| Capability | Description |
|------------|-------------|
| Register applications | Add new SystemForge apps to the federation |
| Detach applications | Remove apps from federation (with data preservation) |
| Define global policies | Create policies that apply across all apps |
| Manage identity providers | Configure federation-wide SSO/SAML/OIDC |
| Configure global roles | Define cross-product role templates |
| Access audit streams | View aggregated audit logs from all apps |
| Manage MSP partnerships | Create and configure MSP relationships |
| Policy conflict resolution | Override when app policies conflict |

#### Constraints

- Cannot directly access application business data
- Cannot manipulate application databases
- Operates only through Product Contract interfaces
- Cannot bypass tenant isolation within apps

#### Example Actions

```json
{
    "action": "federation:app:attach",
    "actor": {
        "type": "human",
        "authority_tier": "federation_admin"
    },
    "resource": {
        "type": "application",
        "app_id": "academy-os"
    },
    "context": {
        "federation_id": "uuid"
    }
}
```

### Tier 2: Managed Service Provider (MSP)

**Scope**: Multi-customer operations across assigned tenants

**Available In**: Both standalone and federated modes

#### Capabilities

| Capability | Description |
|------------|-------------|
| Operate multiple tenants | Access assigned customer tenants |
| Manage tenant configs | Configure tenant-level settings |
| Apply delegated policies | Implement policies within delegation bounds |
| View aggregated metrics | Cross-customer dashboards |
| Provision new tenants | Create tenants for managed customers |
| Delegated user management | Manage users within assigned tenants |
| Support operations | Handle support requests across customers |

#### Constraints

- Cannot override federation-level policies
- Cannot access non-assigned customer tenants
- Cannot modify app-level configurations
- Authority limited to assigned scope (tenants, apps)
- Actions audited with delegation chain

#### Permission Model

```go
type MSPAssignment struct {
    MSPID       uuid.UUID
    AppID       string
    TenantID    uuid.UUID
    Permissions []MSPPermission
    AssignedAt  time.Time
    AssignedBy  uuid.UUID
    ExpiresAt   *time.Time
}

type MSPPermission string
const (
    MSPPermissionRead      MSPPermission = "read"
    MSPPermissionManage    MSPPermission = "manage"
    MSPPermissionProvision MSPPermission = "provision"
    MSPPermissionSupport   MSPPermission = "support"
)
```

### Tier 3: App Owner

**Scope**: Application-level configuration and management

**Available In**: Both standalone and federated modes

#### Capabilities

| Capability | Description |
|------------|-------------|
| Configure app settings | Application-wide configuration |
| Define app roles | Create application-scoped roles |
| Manage integrations | Configure webhooks, APIs, OAuth clients |
| Define policy extensions | App-specific policy rules |
| Feature management | Enable/disable app features |
| App-level analytics | View application-wide metrics |
| Manage app principals | Create service accounts, API keys |

#### Constraints

- Cannot override federation identity core (in federated mode)
- Cannot break tenant isolation
- Cannot modify federation-wide policies
- Cannot access tenant data without explicit permission

#### Standalone vs Federated

| Aspect | Standalone | Federated |
|--------|------------|-----------|
| Identity source | Local | Federation (synced) |
| Policy scope | Full control | Within federation bounds |
| Audit destination | Local | Local + streamed |
| SSO configuration | Local IdP | Federation IdP |

### Tier 4: Tenant Owner

**Scope**: Standard SaaS tenant administration

**Available In**: Both standalone and federated modes

#### Capabilities

| Capability | Description |
|------------|-------------|
| Manage users | Add, remove, update tenant users |
| Assign roles | Grant roles within allowed set |
| Configure features | Tenant-specific feature settings |
| Access tenant data | Full access to tenant's data |
| Billing management | Manage subscription (if applicable) |
| Audit viewing | View tenant's audit log |
| Integration config | Configure tenant-specific integrations |

#### Constraints

- Cannot access other tenants
- Cannot modify app-level configurations
- Cannot override delegated policies (from MSP or Federation)
- Role assignment limited to allowed role set
- Cannot create custom roles (only assign predefined)

## Authority Context

Every authenticated request carries an authority context that determines what actions are permitted.

### Context Structure

```go
type AuthorityContext struct {
    // Identity
    PrincipalID   uuid.UUID
    PrincipalType PrincipalType  // human, application, agent, service

    // Authority Domain
    Tier          AuthorityTier
    DomainType    DomainType
    DomainID      uuid.UUID

    // Effective permissions
    Permissions   []Permission

    // Delegation chain (for agents and MSP)
    Delegation    []DelegationLink

    // Constraints
    Constraints   AuthorityConstraints
}

type AuthorityTier int
const (
    TierFederation AuthorityTier = 1
    TierMSP        AuthorityTier = 2
    TierApp        AuthorityTier = 3
    TierTenant     AuthorityTier = 4
)

type DomainType string
const (
    DomainFederation DomainType = "federation"
    DomainMSP        DomainType = "msp"
    DomainApp        DomainType = "app"
    DomainTenant     DomainType = "tenant"
)
```

### Delegation Chains

When authority is delegated (MSP operations, agent actions), the full chain is tracked:

```go
type DelegationLink struct {
    PrincipalID   uuid.UUID
    PrincipalType PrincipalType
    Tier          AuthorityTier
    DomainType    DomainType
    DomainID      uuid.UUID
    Constraints   DelegationConstraints
    GrantedAt     time.Time
}

type DelegationConstraints struct {
    AllowedActions    []string
    AllowedResources  []string
    AllowedTenants    []uuid.UUID
    MaxTokenLifetime  time.Duration
    RequiresApproval  bool
    ExpiresAt         *time.Time
}
```

## Permission Evaluation

### Evaluation Flow

```
┌─────────────────────────────────────────────────────────┐
│                    Permission Request                    │
│  Actor: human/app/agent/service                         │
│  Action: users:create                                   │
│  Resource: tenant:123/user:456                          │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              1. Authenticate Principal                   │
│  - Validate token/credential                            │
│  - Extract authority context                            │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              2. Check Authority Tier                     │
│  - Verify tier has potential access to domain           │
│  - Federation > MSP > App > Tenant                      │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              3. Apply Delegation Constraints             │
│  - If delegated, intersect constraints                  │
│  - Most restrictive constraint wins                     │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              4. Evaluate Policies                        │
│  - Federation policies (if federated)                   │
│  - App policies                                         │
│  - Tenant policies                                      │
│  - Priority: Explicit Deny > Explicit Allow > Default   │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              5. Return Decision                          │
│  - Allowed/Denied                                       │
│  - Reason and contributing policies                     │
│  - Audit event emitted                                  │
└─────────────────────────────────────────────────────────┘
```

### Evaluation Result

```go
type EvaluationResult struct {
    Allowed     bool
    Reason      string
    Policies    []string     // Contributing policy IDs
    Delegations []string     // Delegation chain if applicable
    Tier        AuthorityTier
    EvaluatedAt time.Time
}
```

## Cross-Tier Interactions

### Federation → App

```json
{
    "scenario": "Federation admin attaches new app",
    "actor_tier": "federation",
    "target_tier": "app",
    "flow": [
        "1. Federation admin initiates attach",
        "2. SystemAuth validates app contract compliance",
        "3. Identity sync begins (federation → app)",
        "4. Policy sync configured",
        "5. Audit streaming enabled",
        "6. App status updated to 'active'"
    ]
}
```

### MSP → Tenant

```json
{
    "scenario": "MSP provisions new tenant",
    "actor_tier": "msp",
    "target_tier": "tenant",
    "flow": [
        "1. MSP requests tenant creation",
        "2. Verify MSP has 'provision' permission",
        "3. Create tenant with MSP assignment",
        "4. Initial admin user created",
        "5. Audit event with delegation chain",
        "6. MSP can now manage tenant"
    ]
}
```

### Agent Delegation

```json
{
    "scenario": "Human delegates to AI agent",
    "actor_tier": "tenant",
    "delegation_target": "agent",
    "flow": [
        "1. Human creates delegation to agent",
        "2. Constraints defined (allowed actions, resources)",
        "3. Agent token issued with constrained capabilities",
        "4. Agent actions carry delegation chain",
        "5. All actions audited with human attribution",
        "6. Human can revoke at any time"
    ]
}
```

## Standalone Mode

In standalone mode (no SystemAuth federation):

### Available Tiers

| Tier | Available | Notes |
|------|-----------|-------|
| Federation | No | Requires SystemAuth |
| MSP | Yes | Local MSP configuration |
| App | Yes | Full control |
| Tenant | Yes | Standard operation |

### Authority Source

- All authority defined locally
- App Owner has maximum authority
- No federation policy overlay
- Local identity management

### Upgrade Path

When joining a federation:

1. Export current identity mappings
2. Map local users to global identities
3. Apply federation policies (additive)
4. Enable audit streaming
5. MSP relationships preserved or remapped

## Security Considerations

### Privilege Escalation Prevention

- Tier boundaries enforced at API level
- Delegation cannot exceed delegator's authority
- Cross-tenant access requires explicit MSP assignment
- Agent capabilities always subset of delegator

### Audit Requirements

All authority-related actions must emit audit events:

```json
{
    "event_type": "authority.delegation.created",
    "actor": {
        "id": "uuid",
        "type": "human",
        "tier": "tenant"
    },
    "target": {
        "id": "uuid",
        "type": "agent"
    },
    "constraints": {
        "allowed_actions": ["documents:read", "documents:create"],
        "expires_at": "2024-12-31T23:59:59Z"
    },
    "context": {
        "tenant_id": "uuid",
        "app_id": "academy-os"
    }
}
```

### Revocation

| Revocation Type | Scope | Effect |
|-----------------|-------|--------|
| Token revocation | Single token | Immediate |
| Delegation revocation | Delegation chain | All child tokens invalid |
| MSP assignment removal | Tenant access | Immediate loss of access |
| App detachment | Federation membership | Graceful transition to standalone |

## Implementation Notes

### For SystemForge Apps

1. Implement authority context extraction from tokens
2. Use Casbin or Cedar for policy evaluation
3. Support delegation chain in JWT claims
4. Emit audit events for all authority changes

### For SystemAuth Integration

1. Expose `/systemforge/policy/evaluate` endpoint
2. Accept and apply synced policies
3. Stream authority-related audit events
4. Support federation token validation

## References

- [Platform Vision](./vision.md)
- [Product Contract](./product-contract.md)
- [SystemAuth PRD](https://github.com/grokify/systemauth/PRD.md)
- OAuth 2.0 (RFC 6749)
- RBAC (NIST INCITS 359)
