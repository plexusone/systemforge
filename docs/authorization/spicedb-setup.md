# SpiceDB Setup Guide

This guide covers setting up SpiceDB for authorization in SystemForge applications.

## Overview

SystemForge uses [SpiceDB](https://authzed.com/spicedb) for fine-grained, relationship-based authorization (ReBAC). SpiceDB implements Google's Zanzibar authorization model, providing:

- **Relationship-based access control**: Define who can do what based on relationships
- **Computed permissions**: Permissions derived from relationship chains
- **Consistent authorization**: Strongly consistent permission checks
- **Scalable**: Handles millions of relationships efficiently

## Deployment Modes

### Embedded Mode (Development)

For development and testing, SystemForge can run an embedded SpiceDB instance.
The embedded server listens in memory inside the application process, so it
opens no network port, and it is guarded by a random preshared key generated at
startup:

```go
import (
    "context"
    "github.com/plexusone/systemforge/authz/rebac/spicedb"
)

func main() {
    ctx := context.Background()

    // Create embedded client with in-memory storage
    client, err := spicedb.NewClient(ctx, spicedb.Config{
        Mode:            "embedded",
        DatastoreEngine: "memory",
    }, nil)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Write schema
    if err := client.WriteSchema(ctx, spicedb.BaseSchema); err != nil {
        log.Fatal(err)
    }

    // Create provider for authorization checks
    provider := spicedb.NewProvider(client)

    // Create syncer for identity integration
    syncer := spicedb.NewSyncer(client)
}
```

#### In-Memory Datastore

Best for unit tests and quick prototyping:

```go
cfg := spicedb.Config{
    Mode:            "embedded",
    DatastoreEngine: "memory",
}
```

#### PostgreSQL Datastore (Embedded)

For development with persistent data:

```go
cfg := spicedb.Config{
    Mode:            "embedded",
    DatastoreEngine: "postgres",
    DatastoreURI:    "postgres://user:pass@localhost:5432/spicedb?sslmode=disable",
}
```

### Remote Mode (Production)

For production, connect to a standalone SpiceDB instance:

```go
cfg := spicedb.Config{
    Mode:     "remote",
    Endpoint: "spicedb.example.com:50051",
    Token:    "your-preshared-key",
    Insecure: false, // Use TLS in production
}
```

## Docker Compose Setup

For local development with a standalone SpiceDB:

```yaml
version: '3.8'

services:
  spicedb:
    image: authzed/spicedb:latest
    command: serve
    ports:
      - "50051:50051"  # gRPC
      - "8443:8443"    # HTTP/REST
      - "9090:9090"    # Metrics
    environment:
      SPICEDB_GRPC_PRESHARED_KEY: "your-secret-key"
      SPICEDB_DATASTORE_ENGINE: postgres
      SPICEDB_DATASTORE_CONN_URI: "postgres://spicedb:spicedb@postgres:5432/spicedb?sslmode=disable"
    depends_on:
      postgres:
        condition: service_healthy

  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: spicedb
      POSTGRES_PASSWORD: spicedb
      POSTGRES_DB: spicedb
    volumes:
      - spicedb-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U spicedb"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  spicedb-data:
```

Start with:

```bash
docker-compose up -d
```

## Configuration Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Mode` | string | `"embedded"` | `"embedded"` or `"remote"` |
| `DatastoreEngine` | string | `"memory"` | For embedded: `"memory"` or `"postgres"` |
| `DatastoreURI` | string | - | PostgreSQL connection string (embedded mode) |
| `Endpoint` | string | - | SpiceDB gRPC endpoint (remote mode) |
| `Token` | string | - | Preshared key for authentication (remote mode) |
| `Insecure` | bool | `false` | Skip TLS verification (remote mode) |

### Environment Variables

```bash
# Storage Configuration
SPICEDB_MODE=remote                              # embedded or remote
SPICEDB_DATASTORE_ENGINE=memory                  # For embedded: memory or postgres
SPICEDB_DATASTORE_URI=postgres://...             # For embedded with postgres

# Remote Connection
SPICEDB_ENDPOINT=spicedb.example.com:50051
SPICEDB_TOKEN=your-preshared-key
SPICEDB_INSECURE=false
```

## Wiring to Identity Services

To sync identity operations to SpiceDB:

```go
import (
    "github.com/plexusone/systemforge/authz/rebac/spicedb"
    "github.com/plexusone/systemforge/identity/organization"
    "github.com/plexusone/systemforge/identity/principal"
)

func setupServices(client *spicedb.Client, entClient *ent.Client) {
    // Create syncer
    syncer := spicedb.NewSyncer(client)

    // Wire to organization service
    orgService := organization.NewService(
        entClient,
        organization.WithAuthzSyncer(syncer),
        organization.WithSyncMode(authz.SyncModeStrict),
    )

    // Wire to principal service
    principalService := principal.NewService(
        entClient,
        principal.WithAuthzSyncer(syncer),
        principal.WithSyncMode(authz.SyncModeStrict),
    )
}
```

### Sync Modes

- **`SyncModeStrict`**: Operations fail if SpiceDB sync fails. Use when authorization must be consistent.
- **`SyncModeEventual`**: Operations succeed, sync failures are logged. Use with a retry mechanism.

## Verification

Test your setup:

```go
func testSetup(ctx context.Context, provider *spicedb.Provider, syncer *spicedb.Syncer) error {
    orgID := uuid.New()
    ownerID := uuid.New()

    // Register organization
    if err := syncer.RegisterOrganization(ctx, orgID, ownerID); err != nil {
        return fmt.Errorf("register org failed: %w", err)
    }

    // Check owner can manage
    owner := authz.Principal{ID: ownerID}
    canManage, err := provider.Can(ctx, owner, "manage", authz.Resource{
        Type: "organization",
        ID:   &orgID,
    })
    if err != nil {
        return fmt.Errorf("permission check failed: %w", err)
    }
    if !canManage {
        return fmt.Errorf("owner should have manage permission")
    }

    return nil
}
```

## Next Steps

- [SpiceDB Schema Guide](spicedb-schema.md) - Understanding the authorization schema
- [Integration Guide](integration.md) - Detailed integration patterns
