# SystemForge Platform Vision

## Overview

SystemForge is an open-source Go framework for building SaaS applications with built-in identity, authorization, tenancy, and audit capabilities. It is designed to support both standalone applications and integration into multi-product platform ecosystems.

## Strategic Positioning

SystemForge represents the open-source foundation of a larger platform strategy:

```
┌─────────────────────────────────────────────────────────────┐
│                    SystemAuth (Commercial)                  │
│           Federation / Governance / Multi-Product            │
├─────────────────────────────────────────────────────────────┤
│                    SystemForge (Open Source)                   │
│              Runtime / Identity / RBAC / Audit               │
├─────────────────────────────────────────────────────────────┤
│                    Your SaaS Application                     │
│                   Domain Logic & Features                    │
└─────────────────────────────────────────────────────────────┘
```

### SystemForge (Open Source)

- Complete SaaS runtime framework
- Local identity management
- Tenant-aware architecture
- Authorization abstraction
- Audit framework
- Fully self-hostable
- No external dependencies required

### SystemAuth (Commercial - Separate Repository)

- Federation layer for multiple SystemForge apps
- Global identity overlay
- Cross-product policy governance
- MSP (Managed Service Provider) support
- Enterprise compliance features

## Design Philosophy

### 1. Complete Without Federation

Every SystemForge application must be fully functional in standalone mode:

- ✅ Local user management
- ✅ Local authentication (password, OAuth)
- ✅ Local RBAC
- ✅ Local audit logging
- ✅ Local tenant management

Federation via SystemAuth is additive, never required.

### 2. Contract-Based Integration

SystemForge defines standard interfaces that enable federation:

- Identity contract
- Authorization contract
- Audit contract
- Metadata contract

Applications implementing these contracts can optionally integrate with SystemAuth.

### 3. Portable Applications

SystemForge applications can:

- Run independently
- Join a federation
- Leave a federation
- Transfer between organizations
- Merge into unified platforms

This supports real-world scenarios like:

- Acquisitions
- Divestitures
- Partnership integrations
- White-label deployments

## Authority Model

SystemForge implements a four-tier authority model designed for multi-product ecosystems:

### Tier 1: Federation (SystemAuth Only)

- Platform-wide governance
- Cross-app identity
- Global policies
- Managed via SystemAuth

### Tier 2: MSP (Managed Service Provider)

- Multi-customer operations
- Delegated administration
- Partner-level access

### Tier 3: Application

- App-level configuration
- App-scoped roles
- Feature management

### Tier 4: Tenant

- Standard SaaS administration
- User management
- Tenant-level features

## Principal-Centric Identity

SystemForge uses a principal-centric identity model that supports:

| Principal Type | Description | Auth Method |
|---------------|-------------|-------------|
| Human | Interactive users | Password, OAuth, SSO |
| Application | OAuth clients | client_credentials |
| Agent | AI assistants | Delegated auth |
| Service | Backend systems | JWT bearer, API key |

This unified model enables:

- Consistent authorization across principal types
- Delegation chains for AI agent actions
- Cross-app identity mapping in federated mode

## Dual-Mode Architecture

Every SystemForge application supports two operational modes:

### Standalone Mode

```
┌─────────────────────────────────────┐
│         SystemForge Application        │
│  ┌─────────────────────────────────┐│
│  │      Local Identity Store       ││
│  ├─────────────────────────────────┤│
│  │       Local RBAC Engine         ││
│  ├─────────────────────────────────┤│
│  │        Local Audit Log          ││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
```

- Self-contained
- No external dependencies
- Full functionality

### Federated Mode

```
┌─────────────────────────────────────────────┐
│               SystemAuth                    │
│  ┌────────────┬────────────┬──────────────┐ │
│  │  Identity  │   Policy   │    Audit     │ │
│  │   Overlay  │  Governance│  Aggregation │ │
│  └────────────┴────────────┴──────────────┘ │
└─────────────────────────────────────────────┘
         │              │              │
         ▼              ▼              ▼
┌─────────────────────────────────────────────┐
│         SystemForge Application                │
│  ┌────────────┬────────────┬──────────────┐ │
│  │   Local    │   Local    │    Local     │ │
│  │  Identity  │    RBAC    │    Audit     │ │
│  │  (synced)  │  (synced)  │  (streamed)  │ │
│  └────────────┴────────────┴──────────────┘ │
└─────────────────────────────────────────────┘
```

- Identity delegated to federation
- Policies synchronized
- Audit streamed to aggregator
- Still functions if federation unavailable

## Evolution Path

### Phase 1: Single-Product Excellence (Current)

- Build production-ready SaaS applications
- Harden identity, RBAC, audit
- Validate abstractions across multiple apps

### Phase 2: Standardized Contracts

- Formalize Product Contract specification
- Implement federation-ready endpoints
- Design authority model

### Phase 3: Federation (SystemAuth)

- Enable optional federation mode
- Shared identity overlay
- Cross-app policy governance

### Phase 4: Platform Ecosystem

- Multi-product orchestration
- App lifecycle management
- Enterprise governance

## Comparison with Existing Solutions

| Aspect | Salesforce | AWS | SystemForge + SystemAuth |
|--------|-----------|-----|------------------------|
| Identity | Proprietary | IAM | Open standard |
| Multi-product | Vertically integrated | Service-based | Federated |
| Detachability | Difficult | N/A | First-class |
| Hosting | SaaS only | Cloud only | Self-host or managed |
| Source | Closed | Closed | Open core |

## Target Users

### Framework Users (SystemForge)

- Startups building SaaS products
- Agencies building client applications
- Enterprise teams building internal tools

### Platform Operators (SystemAuth)

- Organizations running multiple SaaS products
- MSPs managing customer portfolios
- Enterprises consolidating applications

## Success Criteria

### SystemForge Adoption

- Production deployments across varied domains
- Active community contributions
- Stable API with clear versioning

### Platform Viability

- Successful federation of 2+ production apps
- Clean app attachment/detachment
- MSP operational deployment

## References

- [Product Contract Specification](./product-contract.md)
- [Authority Model](./authority-model.md)
- [SystemAuth PRD](https://github.com/grokify/systemauth/PRD.md)
- [SystemAuth TRD](https://github.com/grokify/systemauth/TRD.md)
