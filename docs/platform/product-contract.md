# SystemForge Product Contract Specification

**Version**: 1.0 (Draft)
**Status**: In Development

## Overview

The SystemForge Product Contract defines the standardized interfaces that SystemForge applications must implement to participate in federated deployments via SystemAuth.

Applications implementing this contract can:

- Operate in standalone mode (default)
- Join a SystemAuth federation
- Leave a federation cleanly
- Transfer between federations

## Design Principles

### 1. Federation is Optional

All contract endpoints are optional for standalone operation. Applications must function fully without implementing federation endpoints.

### 2. Additive Integration

Federation adds capabilities; it never restricts standalone functionality.

### 3. Graceful Degradation

If federation becomes unavailable, applications should continue operating using local state.

## Contract Endpoints

### Metadata Endpoint

**Purpose**: Expose application capabilities and configuration to SystemAuth.

```
GET /systemforge/meta

Response:
{
    "app_id": "my-saas-app",
    "display_name": "My SaaS Application",
    "version": "1.2.0",
    "contract_version": "1.0",
    "capabilities": [
        "identity",
        "rbac",
        "audit",
        "tenancy"
    ],
    "endpoints": {
        "identity": "/systemforge/identity",
        "policy": "/systemforge/policy",
        "audit": "/systemforge/audit",
        "health": "/systemforge/health"
    },
    "federation": {
        "status": "standalone",
        "federation_id": null
    }
}
```

#### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| app_id | string | Yes | Unique application identifier |
| display_name | string | Yes | Human-readable name |
| version | string | Yes | Application version (semver) |
| contract_version | string | Yes | Contract version implemented |
| capabilities | []string | Yes | Supported capabilities |
| endpoints | object | Yes | Endpoint paths |
| federation | object | No | Federation status |

#### Capabilities

| Capability | Description |
|------------|-------------|
| identity | Principal management |
| rbac | Role-based access control |
| audit | Audit event emission |
| tenancy | Multi-tenant support |
| delegation | Agent delegation support |

### Identity Interface

**Purpose**: Enable identity synchronization and lookup.

#### List Principals

```
GET /systemforge/identity/principals?type={type}&tenant_id={tenant_id}&limit={limit}&cursor={cursor}

Response:
{
    "principals": [
        {
            "id": "uuid",
            "type": "human",
            "identifier": "user@example.com",
            "display_name": "John Doe",
            "active": true,
            "organization_id": "uuid",
            "capabilities": {
                "can_access_ui": true,
                "can_delegate": true
            },
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }
    ],
    "next_cursor": "string",
    "total": 100
}
```

#### Get Principal

```
GET /systemforge/identity/principals/{id}

Response:
{
    "id": "uuid",
    "type": "human",
    "identifier": "user@example.com",
    "display_name": "John Doe",
    "active": true,
    "organization_id": "uuid",
    "capabilities": {...},
    "human": {
        "email": "user@example.com",
        "given_name": "John",
        "family_name": "Doe"
    },
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
}
```

#### Lookup Principal

```
POST /systemforge/identity/principals/lookup

Request:
{
    "identifier": "user@example.com"
}

Response:
{
    "principal": {...}
}
```

#### Sync Identity (Federation Mode)

```
POST /systemforge/identity/sync

Request:
{
    "federation_id": "uuid",
    "sync_token": "string",
    "principals": [
        {
            "global_id": "uuid",
            "identifier": "user@example.com",
            "display_name": "John Doe",
            "attributes": {...}
        }
    ]
}

Response:
{
    "synced": ["uuid", "uuid"],
    "failed": [
        {
            "global_id": "uuid",
            "error": "conflict"
        }
    ],
    "sync_token": "string"
}
```

#### List Tenants

```
GET /systemforge/identity/tenants

Response:
{
    "tenants": [
        {
            "id": "uuid",
            "name": "Acme Corp",
            "slug": "acme-corp",
            "active": true,
            "created_at": "2024-01-01T00:00:00Z"
        }
    ]
}
```

### Policy Interface

**Purpose**: Enable policy synchronization and evaluation.

#### List Roles

```
GET /systemforge/policy/roles

Response:
{
    "roles": [
        {
            "id": "admin",
            "display_name": "Administrator",
            "description": "Full administrative access",
            "permissions": ["*"],
            "scope": "tenant"
        }
    ]
}
```

#### List Permissions

```
GET /systemforge/policy/permissions

Response:
{
    "permissions": [
        {
            "id": "users:read",
            "display_name": "Read Users",
            "description": "View user information",
            "resource_type": "users",
            "actions": ["read", "list"]
        }
    ]
}
```

#### Sync Policies (Federation Mode)

```
POST /systemforge/policy/sync

Request:
{
    "federation_id": "uuid",
    "sync_token": "string",
    "policies": [
        {
            "id": "uuid",
            "name": "Global Admin Policy",
            "rules": [...],
            "priority": 100
        }
    ],
    "removed_ids": ["uuid"]
}

Response:
{
    "applied": ["uuid"],
    "failed": [
        {
            "id": "uuid",
            "error": "invalid_rule"
        }
    ],
    "sync_token": "string"
}
```

#### Evaluate Policy

```
POST /systemforge/policy/evaluate

Request:
{
    "principal_id": "uuid",
    "action": "users:read",
    "resource": {
        "type": "user",
        "id": "uuid"
    },
    "context": {
        "tenant_id": "uuid",
        "ip_address": "192.168.1.1"
    }
}

Response:
{
    "allowed": true,
    "reason": "role:admin grants users:*",
    "policies": ["local:admin-policy"],
    "evaluated_at": "2024-01-01T00:00:00Z"
}
```

### Audit Interface

**Purpose**: Configure audit event streaming.

#### Get Stream Configuration

```
GET /systemforge/audit/stream/config

Response:
{
    "enabled": true,
    "endpoint": "https://systemauth.example.com/audit/ingest",
    "batch_size": 100,
    "flush_interval_ms": 5000,
    "auth_method": "bearer",
    "last_sequence": 12345
}
```

#### Update Stream Configuration

```
PUT /systemforge/audit/stream/config

Request:
{
    "enabled": true,
    "endpoint": "https://systemauth.example.com/audit/ingest",
    "auth_token": "bearer-token",
    "batch_size": 100,
    "flush_interval_ms": 5000
}

Response:
{
    "status": "configured",
    "test_result": "success"
}
```

#### Acknowledge Events

```
POST /systemforge/audit/stream/ack

Request:
{
    "sequence": 12345,
    "timestamp": "2024-01-01T00:00:00Z"
}

Response:
{
    "acknowledged": true,
    "next_sequence": 12346
}
```

### Health Interface

**Purpose**: Monitor application and federation health.

#### Application Health

```
GET /systemforge/health

Response:
{
    "status": "healthy",
    "version": "1.2.0",
    "uptime_seconds": 86400,
    "checks": {
        "database": "healthy",
        "cache": "healthy",
        "identity": "healthy"
    }
}
```

#### Federation Health

```
GET /systemforge/health/federation

Response:
{
    "federation_status": "connected",
    "federation_id": "uuid",
    "last_sync": "2024-01-01T00:00:00Z",
    "sync_lag_seconds": 5,
    "checks": {
        "identity_sync": "healthy",
        "policy_sync": "healthy",
        "audit_stream": "healthy"
    }
}
```

## Authentication

### Service-to-Service Authentication

SystemAuth authenticates to applications using signed JWTs:

```go
type SystemAuthServiceToken struct {
    // Standard JWT claims
    Issuer    string `json:"iss"` // "systemauth.example.com"
    Subject   string `json:"sub"` // "federation:{federation_id}"
    Audience  string `json:"aud"` // "{app_id}"
    IssuedAt  int64  `json:"iat"`
    ExpiresAt int64  `json:"exp"`

    // SystemAuth claims
    FederationID string   `json:"federation_id"`
    Permissions  []string `json:"permissions"`
}
```

Applications MUST validate:

1. Token signature against SystemAuth's public key
2. Issuer matches expected SystemAuth instance
3. Audience matches application's app_id
4. Token is not expired
5. Required permissions are present

### Permission Scopes

| Permission | Description |
|------------|-------------|
| identity:read | Read principals and tenants |
| identity:sync | Synchronize identity data |
| policy:read | Read roles and permissions |
| policy:sync | Synchronize policies |
| audit:config | Configure audit streaming |
| health:read | Read health status |

## Audit Event Schema

Applications must emit audit events in this standardized format:

```json
{
    "id": "uuid",
    "timestamp": "2024-01-01T00:00:00Z",
    "event_type": "user.created",
    "action": "create",

    "actor": {
        "id": "uuid",
        "type": "human",
        "identifier": "admin@example.com"
    },

    "resource": {
        "type": "user",
        "id": "uuid",
        "identifier": "newuser@example.com"
    },

    "context": {
        "tenant_id": "uuid",
        "session_id": "string",
        "client_ip": "192.168.1.1",
        "user_agent": "Mozilla/5.0..."
    },

    "outcome": "success",
    "details": {
        "changes": {
            "email": "newuser@example.com",
            "role": "member"
        }
    }
}
```

### Required Event Types

| Event Type | When to Emit |
|------------|--------------|
| principal.created | New principal created |
| principal.updated | Principal modified |
| principal.deleted | Principal deleted |
| principal.login | Successful authentication |
| principal.logout | Session terminated |
| role.assigned | Role assigned to principal |
| role.revoked | Role removed from principal |
| permission.evaluated | Access decision made |
| tenant.created | New tenant created |
| tenant.updated | Tenant modified |

## Implementation Guidelines

### Standalone Mode

When not federated:

1. All endpoints return local data only
2. `/systemforge/health/federation` returns `federation_status: "standalone"`
3. Sync endpoints return `501 Not Implemented`

### Federation Attachment

When joining a federation:

1. SystemAuth calls `/systemforge/meta` to validate compatibility
2. SystemAuth calls identity sync endpoints to map users
3. SystemAuth configures audit streaming
4. Application updates federation status in metadata

### Federation Detachment

When leaving a federation:

1. SystemAuth notifies application of pending detachment
2. Application exports identity mappings
3. Audit streaming is disabled
4. Application reverts to standalone mode
5. Local data is preserved

### Error Handling

Standard error response format:

```json
{
    "error": {
        "code": "IDENTITY_SYNC_CONFLICT",
        "message": "Principal with identifier already exists",
        "details": {
            "identifier": "user@example.com",
            "existing_id": "uuid"
        }
    }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| NOT_FEDERATED | 503 | App not in federation mode |
| SYNC_IN_PROGRESS | 409 | Another sync operation running |
| IDENTITY_CONFLICT | 409 | Identity mapping conflict |
| POLICY_INVALID | 400 | Invalid policy definition |
| UNAUTHORIZED | 401 | Invalid or missing auth |
| FORBIDDEN | 403 | Insufficient permissions |

## Versioning

Contract versions follow semantic versioning:

- **Major**: Breaking changes to required endpoints
- **Minor**: New optional endpoints or fields
- **Patch**: Bug fixes, clarifications

Applications declare supported contract version in metadata.
SystemAuth validates compatibility before attachment.

## Security Considerations

### Data Protection

- All endpoints must use TLS
- Sensitive data encrypted at rest
- PII handled per compliance requirements

### Authentication

- All federation endpoints require authentication
- Tokens must be validated on every request
- Short token lifetimes (< 1 hour recommended)

### Authorization

- Validate permissions on every request
- Log all access attempts
- Rate limit sync operations

## References

- [Authority Model](./authority-model.md)
- [Platform Vision](./vision.md)
- OAuth 2.0 (RFC 6749)
- JWT (RFC 7519)
