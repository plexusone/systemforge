package contract

import (
	"time"

	"github.com/google/uuid"
)

// MetadataResponse is returned by GET /systemforge/meta.
type MetadataResponse struct {
	Body struct {
		AppID           string            `json:"app_id" doc:"Unique application identifier" example:"my-saas-app"`
		DisplayName     string            `json:"display_name" doc:"Human-readable application name" example:"My SaaS Application"`
		Version         string            `json:"version" doc:"Application version (semver)" example:"1.2.0"`
		ContractVersion string            `json:"contract_version" doc:"Contract specification version" example:"1.0"`
		Capabilities    []string          `json:"capabilities" doc:"Supported contract capabilities" example:"[\"identity\", \"rbac\", \"audit\"]"`
		Endpoints       map[string]string `json:"endpoints" doc:"Endpoint paths by capability"`
		Federation      FederationStatus  `json:"federation" doc:"Current federation status"`
	}
}

// FederationStatus tracks standalone vs federated mode.
type FederationStatus struct {
	Status       string     `json:"status" doc:"Federation status" enum:"standalone,federated" example:"standalone"`
	FederationID *uuid.UUID `json:"federation_id,omitempty" doc:"Federation identifier when federated"`
}

// FederationStatusStandalone is the status value for standalone mode.
const FederationStatusStandalone = "standalone"

// FederationStatusFederated is the status value for federated mode.
const FederationStatusFederated = "federated"

// ContractPrincipal represents a principal in contract responses.
type ContractPrincipal struct {
	ID             uuid.UUID        `json:"id" doc:"Principal unique identifier" format:"uuid"`
	Type           string           `json:"type" doc:"Principal type" enum:"human,application,agent,service" example:"human"`
	Identifier     string           `json:"identifier" doc:"Unique identifier (email, client_id, etc.)" example:"user@example.com"`
	DisplayName    string           `json:"display_name" doc:"Human-readable display name" example:"John Doe"`
	Active         bool             `json:"active" doc:"Whether the principal is active" example:"true"`
	OrganizationID *uuid.UUID       `json:"organization_id,omitempty" doc:"Organization this principal belongs to" format:"uuid"`
	Capabilities   map[string]bool  `json:"capabilities,omitempty" doc:"Principal capabilities"`
	CreatedAt      time.Time        `json:"created_at" doc:"Creation timestamp" format:"date-time"`
	UpdatedAt      time.Time        `json:"updated_at" doc:"Last update timestamp" format:"date-time"`
	Human          *ContractHuman   `json:"human,omitempty" doc:"Human-specific data (when type=human)"`
	Application    *ContractApp     `json:"application,omitempty" doc:"Application-specific data (when type=application)"`
	Agent          *ContractAgent   `json:"agent,omitempty" doc:"Agent-specific data (when type=agent)"`
	Service        *ContractService `json:"service,omitempty" doc:"Service-specific data (when type=service)"`
}

// ContractHuman represents human-specific data in contract responses.
type ContractHuman struct {
	Email      string `json:"email" doc:"Email address" format:"email" example:"user@example.com"`
	GivenName  string `json:"given_name,omitempty" doc:"Given/first name" example:"John"`
	FamilyName string `json:"family_name,omitempty" doc:"Family/last name" example:"Doe"`
}

// ContractApp represents application-specific data in contract responses.
type ContractApp struct {
	ClientID    string `json:"client_id" doc:"OAuth client ID" example:"my-app-client"`
	AppType     string `json:"app_type" doc:"Application type" enum:"web,spa,native,machine" example:"web"`
	FirstParty  bool   `json:"first_party" doc:"Whether this is a first-party application" example:"true"`
	Description string `json:"description,omitempty" doc:"Application description"`
}

// ContractAgent represents agent-specific data in contract responses.
type ContractAgent struct {
	ModelID              string     `json:"model_id" doc:"AI model identifier" example:"claude-3-opus"`
	Version              string     `json:"version,omitempty" doc:"Agent version"`
	DelegatingPrincipal  *uuid.UUID `json:"delegating_principal_id,omitempty" doc:"Principal that delegated to this agent" format:"uuid"`
	RequiresConfirmation bool       `json:"requires_confirmation" doc:"Whether actions require confirmation" example:"true"`
}

// ContractService represents service-specific data in contract responses.
type ContractService struct {
	ServiceType string `json:"service_type" doc:"Type of service" example:"backend"`
	Description string `json:"description,omitempty" doc:"Service description"`
}

// PrincipalsListInput defines query parameters for listing principals.
type PrincipalsListInput struct {
	Type     string `query:"type" doc:"Filter by principal type" enum:"human,application,agent,service"`
	TenantID string `query:"tenant_id" doc:"Filter by tenant/organization ID" format:"uuid"`
	Limit    int    `query:"limit" doc:"Maximum number of results" minimum:"1" maximum:"1000" default:"100"`
	Cursor   string `query:"cursor" doc:"Pagination cursor"`
}

// PrincipalsListOutput is returned by GET /systemforge/identity/principals.
type PrincipalsListOutput struct {
	Body struct {
		Principals []ContractPrincipal `json:"principals" doc:"List of principals"`
		NextCursor string              `json:"next_cursor,omitempty" doc:"Cursor for next page"`
		Total      int                 `json:"total" doc:"Total number of principals" example:"42"`
	}
}

// PrincipalGetInput defines path parameters for getting a principal.
type PrincipalGetInput struct {
	ID string `path:"id" doc:"Principal ID" format:"uuid"`
}

// PrincipalGetOutput is returned by GET /systemforge/identity/principals/{id}.
type PrincipalGetOutput struct {
	Body ContractPrincipal
}

// LookupInput is the body for POST /systemforge/identity/principals/lookup.
type LookupInput struct {
	Body struct {
		Identifier string `json:"identifier" doc:"Identifier to look up (email, client_id, etc.)" required:"true" example:"user@example.com"`
	}
}

// LookupOutput is returned by POST /systemforge/identity/principals/lookup.
type LookupOutput struct {
	Body struct {
		Principal *ContractPrincipal `json:"principal" doc:"Found principal, or null if not found"`
	}
}

// Tenant represents an organization/tenant in contract responses.
type Tenant struct {
	ID        uuid.UUID `json:"id" doc:"Tenant unique identifier" format:"uuid"`
	Name      string    `json:"name" doc:"Tenant name" example:"Acme Corp"`
	Slug      string    `json:"slug,omitempty" doc:"URL-friendly slug" example:"acme-corp"`
	Active    bool      `json:"active" doc:"Whether the tenant is active" example:"true"`
	CreatedAt time.Time `json:"created_at" doc:"Creation timestamp" format:"date-time"`
}

// TenantsListOutput is returned by GET /systemforge/identity/tenants.
type TenantsListOutput struct {
	Body struct {
		Tenants []Tenant `json:"tenants" doc:"List of tenants"`
	}
}

// Role represents a role in contract responses.
type Role struct {
	ID          string   `json:"id" doc:"Role identifier" example:"admin"`
	DisplayName string   `json:"display_name" doc:"Human-readable role name" example:"Administrator"`
	Description string   `json:"description,omitempty" doc:"Role description" example:"Full administrative access"`
	Permissions []string `json:"permissions" doc:"Permissions granted by this role"`
	Scope       string   `json:"scope,omitempty" doc:"Role scope" enum:"tenant,platform" example:"tenant"`
	Level       int      `json:"level,omitempty" doc:"Hierarchy level (higher = more access)" example:"80"`
}

// RolesListOutput is returned by GET /systemforge/policy/roles.
type RolesListOutput struct {
	Body struct {
		Roles []Role `json:"roles" doc:"List of roles"`
	}
}

// Permission represents a permission in contract responses.
type Permission struct {
	ID           string   `json:"id" doc:"Permission identifier" example:"users:read"`
	DisplayName  string   `json:"display_name" doc:"Human-readable permission name" example:"Read Users"`
	Description  string   `json:"description,omitempty" doc:"Permission description"`
	ResourceType string   `json:"resource_type,omitempty" doc:"Resource type this permission applies to" example:"users"`
	Actions      []string `json:"actions,omitempty" doc:"Actions this permission grants" example:"[\"read\", \"list\"]"`
}

// PermissionsListOutput is returned by GET /systemforge/policy/permissions.
type PermissionsListOutput struct {
	Body struct {
		Permissions []Permission `json:"permissions" doc:"List of permissions"`
	}
}

// ResourceRef references a resource for policy evaluation.
type ResourceRef struct {
	Type string    `json:"type" doc:"Resource type" required:"true" example:"document"`
	ID   uuid.UUID `json:"id" doc:"Resource identifier" required:"true" format:"uuid"`
}

// EvaluateInput is the body for POST /systemforge/policy/evaluate.
type EvaluateInput struct {
	Body struct {
		PrincipalID uuid.UUID      `json:"principal_id" doc:"Principal to evaluate" required:"true" format:"uuid"`
		Action      string         `json:"action" doc:"Action to evaluate" required:"true" example:"users:read"`
		Resource    ResourceRef    `json:"resource" doc:"Resource to evaluate against" required:"true"`
		Context     map[string]any `json:"context,omitempty" doc:"Additional context for evaluation"`
	}
}

// EvaluateOutput is returned by POST /systemforge/policy/evaluate.
type EvaluateOutput struct {
	Body struct {
		Allowed     bool      `json:"allowed" doc:"Whether the action is allowed" example:"true"`
		Reason      string    `json:"reason" doc:"Reason for the decision" example:"role:admin grants users:*"`
		Policies    []string  `json:"policies,omitempty" doc:"Policies that contributed to the decision"`
		EvaluatedAt time.Time `json:"evaluated_at" doc:"Timestamp of evaluation" format:"date-time"`
	}
}

// HealthOutput is returned by GET /systemforge/health.
type HealthOutput struct {
	Body struct {
		Status        string            `json:"status" doc:"Overall health status" enum:"healthy,degraded,unhealthy" example:"healthy"`
		Version       string            `json:"version" doc:"Application version" example:"1.2.0"`
		UptimeSeconds int64             `json:"uptime_seconds" doc:"Seconds since startup" example:"86400"`
		Checks        map[string]string `json:"checks,omitempty" doc:"Health check results by component"`
	}
}

// FederationHealthOutput is returned by GET /systemforge/health/federation.
type FederationHealthOutput struct {
	Body struct {
		FederationStatus string            `json:"federation_status" doc:"Federation connection status" enum:"standalone,connected,disconnected" example:"standalone"`
		FederationID     *uuid.UUID        `json:"federation_id,omitempty" doc:"Federation identifier" format:"uuid"`
		LastSync         *time.Time        `json:"last_sync,omitempty" doc:"Last sync timestamp" format:"date-time"`
		SyncLagSeconds   int               `json:"sync_lag_seconds,omitempty" doc:"Seconds since last sync" example:"5"`
		Checks           map[string]string `json:"checks,omitempty" doc:"Federation health check results"`
	}
}

// SyncPrincipal represents a principal to sync from SystemAuth.
type SyncPrincipal struct {
	GlobalID    uuid.UUID      `json:"global_id" doc:"Global principal identifier" required:"true" format:"uuid"`
	Identifier  string         `json:"identifier" doc:"Principal identifier" required:"true" example:"user@example.com"`
	DisplayName string         `json:"display_name" doc:"Display name" required:"true" example:"John Doe"`
	Attributes  map[string]any `json:"attributes,omitempty" doc:"Additional attributes"`
}

// IdentitySyncInput is the body for POST /systemforge/identity/sync.
type IdentitySyncInput struct {
	Body struct {
		FederationID uuid.UUID       `json:"federation_id" doc:"Federation identifier" required:"true" format:"uuid"`
		SyncToken    string          `json:"sync_token" doc:"Sync token for idempotency" required:"true"`
		Principals   []SyncPrincipal `json:"principals" doc:"Principals to sync" required:"true"`
	}
}

// SyncFailure represents a failed sync operation.
type SyncFailure struct {
	GlobalID uuid.UUID `json:"global_id" doc:"Failed principal identifier" format:"uuid"`
	Error    string    `json:"error" doc:"Error message" example:"conflict"`
}

// IdentitySyncOutput is returned by POST /systemforge/identity/sync.
type IdentitySyncOutput struct {
	Body struct {
		Synced    []uuid.UUID   `json:"synced" doc:"Successfully synced principal IDs"`
		Failed    []SyncFailure `json:"failed" doc:"Failed sync operations"`
		SyncToken string        `json:"sync_token" doc:"Updated sync token"`
	}
}

// SyncPolicy represents a policy to sync from SystemAuth.
type SyncPolicy struct {
	ID       uuid.UUID `json:"id" doc:"Policy identifier" required:"true" format:"uuid"`
	Name     string    `json:"name" doc:"Policy name" required:"true" example:"Global Admin Policy"`
	Rules    []any     `json:"rules" doc:"Policy rules"`
	Priority int       `json:"priority" doc:"Policy priority (higher = evaluated first)" example:"100"`
}

// PolicySyncInput is the body for POST /systemforge/policy/sync.
type PolicySyncInput struct {
	Body struct {
		FederationID uuid.UUID    `json:"federation_id" doc:"Federation identifier" required:"true" format:"uuid"`
		SyncToken    string       `json:"sync_token" doc:"Sync token for idempotency" required:"true"`
		Policies     []SyncPolicy `json:"policies" doc:"Policies to sync" required:"true"`
		RemovedIDs   []uuid.UUID  `json:"removed_ids,omitempty" doc:"Policy IDs to remove"`
	}
}

// PolicySyncFailure represents a failed policy sync operation.
type PolicySyncFailure struct {
	ID    uuid.UUID `json:"id" doc:"Failed policy identifier" format:"uuid"`
	Error string    `json:"error" doc:"Error message" example:"invalid_rule"`
}

// PolicySyncOutput is returned by POST /systemforge/policy/sync.
type PolicySyncOutput struct {
	Body struct {
		Applied   []uuid.UUID         `json:"applied" doc:"Successfully applied policy IDs"`
		Failed    []PolicySyncFailure `json:"failed" doc:"Failed policy operations"`
		SyncToken string              `json:"sync_token" doc:"Updated sync token"`
	}
}

// AuditStreamConfig holds audit streaming configuration.
type AuditStreamConfig struct {
	Enabled         bool   `json:"enabled" doc:"Whether streaming is enabled" example:"true"`
	Endpoint        string `json:"endpoint,omitempty" doc:"Streaming endpoint URL" format:"uri" example:"https://systemauth.example.com/audit/ingest"`
	BatchSize       int    `json:"batch_size,omitempty" doc:"Events per batch" minimum:"1" maximum:"1000" example:"100"`
	FlushIntervalMs int    `json:"flush_interval_ms,omitempty" doc:"Flush interval in milliseconds" minimum:"100" example:"5000"`
	AuthMethod      string `json:"auth_method,omitempty" doc:"Authentication method" enum:"bearer" example:"bearer"`
	LastSequence    int64  `json:"last_sequence,omitempty" doc:"Last recorded sequence number" example:"12345"`
}

// AuditStreamConfigOutput is returned by GET /systemforge/audit/stream/config.
type AuditStreamConfigOutput struct {
	Body AuditStreamConfig
}

// UpdateAuditStreamConfigInput is the body for PUT /systemforge/audit/stream/config.
type UpdateAuditStreamConfigInput struct {
	Body struct {
		Enabled         bool   `json:"enabled" doc:"Enable or disable streaming" required:"true"`
		Endpoint        string `json:"endpoint" doc:"Streaming endpoint URL" required:"true" format:"uri"`
		BearerToken     string `json:"bearer_token,omitempty" doc:"Bearer token for authentication"` // #nosec G117
		BatchSize       int    `json:"batch_size,omitempty" doc:"Events per batch" minimum:"1" maximum:"1000"`
		FlushIntervalMs int    `json:"flush_interval_ms,omitempty" doc:"Flush interval in milliseconds" minimum:"100"`
	}
}

// UpdateAuditStreamConfigOutput is returned by PUT /systemforge/audit/stream/config.
type UpdateAuditStreamConfigOutput struct {
	Body struct {
		Status     string `json:"status" doc:"Configuration status" enum:"configured,failed" example:"configured"`
		TestResult string `json:"test_result,omitempty" doc:"Connection test result" example:"success"`
	}
}

// AuditAckInput is the body for POST /systemforge/audit/stream/ack.
type AuditAckInput struct {
	Body struct {
		Sequence  int64     `json:"sequence" doc:"Sequence number to acknowledge" required:"true" example:"12345"`
		Timestamp time.Time `json:"timestamp" doc:"Acknowledgment timestamp" required:"true" format:"date-time"`
	}
}

// AuditAckOutput is returned by POST /systemforge/audit/stream/ack.
type AuditAckOutput struct {
	Body struct {
		Acknowledged bool  `json:"acknowledged" doc:"Whether acknowledgment was successful" example:"true"`
		NextSequence int64 `json:"next_sequence" doc:"Next expected sequence number" example:"12346"`
	}
}
