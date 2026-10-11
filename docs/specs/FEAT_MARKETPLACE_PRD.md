# PRD: SystemForge Marketplace & Entitlements

> **Status**: Draft
>
> This PRD defines the requirements for a shared marketplace and entitlements system that can be used by SystemForge-powered applications.

## Overview

SystemForge Marketplace provides a unified framework for two-sided marketplace applications where:

- **Creators** (Publishers/Tenants) create and sell digital products
- **Consumers** (Organizations) subscribe to platforms and purchase products

This module enables consistent pricing, licensing, and entitlement patterns across SystemForge applications like App1 (courses) and App2 (dashboards).

## Goals

1. **Unified Entitlements**: Common licensing model across applications
2. **Flexible Pricing**: Support multiple pricing models (free, one-time, subscription, per-seat)
3. **Authorization Integration**: SpiceDB-native license checking
4. **Payment Abstraction**: Stripe Connect integration with revenue sharing
5. **App Extensibility**: Easy to extend for domain-specific products

## Target Applications

| Application | Creator Entity | Consumer Entity | Products |
|-------------|----------------|-----------------|----------|
| **App1** | Tenant (Course Giver) | Organization (Course Taker) | Courses |
| **App2** | Publisher | Organization | Dashboard Templates, Data Connectors |
| **Future Apps** | - | - | Any digital product |

## User Stories

### Creator Stories

**US-1**: As a creator, I can list my products on the marketplace with flexible pricing.

**US-2**: As a creator, I can track sales, revenue, and usage analytics.

**US-3**: As a creator, I can set different pricing tiers (free, paid, enterprise).

**US-4**: As a creator, I can receive payouts for my sales via Stripe Connect.

### Consumer Stories

**US-5**: As an organization admin, I can browse and purchase products from the marketplace.

**US-6**: As an organization admin, I can manage licenses (view, transfer, cancel).

**US-7**: As an organization member, I can access products my organization has licensed.

**US-8**: As an organization admin, I can manage seat assignments for per-seat licenses.

### Platform Stories

**US-9**: As a platform operator, I can configure revenue sharing percentages.

**US-10**: As a platform operator, I can moderate marketplace listings.

**US-11**: As a platform operator, I can view platform-wide analytics.

## Entity Model

### Core Entities

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MARKETPLACE ENTITY MODEL                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐           ┌─────────────────┐                          │
│  │  CreatorOrg     │           │  ConsumerOrg    │                          │
│  │  (Publisher/    │           │  (Organization) │                          │
│  │   Tenant)       │           │                 │                          │
│  │                 │           │                 │                          │
│  │  - owner        │           │  - owner        │                          │
│  │  - admin        │           │  - admin        │                          │
│  │  - creator      │           │  - member       │                          │
│  │  - reviewer     │           │  - viewer       │                          │
│  └────────┬────────┘           └────────┬────────┘                          │
│           │                             │                                    │
│           │ creates                     │ purchases                          │
│           ▼                             │                                    │
│  ┌─────────────────┐                    │                                    │
│  │    Listing      │◀───────────────────┘                                    │
│  │                 │                                                         │
│  │  - product_type │                                                         │
│  │  - product_id   │                                                         │
│  │  - pricing      │                                                         │
│  │  - status       │                                                         │
│  └────────┬────────┘                                                         │
│           │                                                                  │
│           │ grants                                                           │
│           ▼                                                                  │
│  ┌─────────────────┐           ┌─────────────────┐                          │
│  │    License      │           │  Subscription   │                          │
│  │                 │           │  (Platform)     │                          │
│  │  - org_id       │           │                 │                          │
│  │  - listing_id   │           │  - org_id       │                          │
│  │  - type         │           │  - plan_tier    │                          │
│  │  - seats        │           │  - stripe_id    │                          │
│  └─────────────────┘           └─────────────────┘                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Entity Definitions

#### Listing

A marketplace listing represents a product available for purchase.

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique identifier |
| creator_org_id | UUID | Creator organization |
| product_type | string | App-specific type (course, dashboard_template, etc.) |
| product_id | UUID | Reference to the actual product |
| pricing_model | enum | free, one_time, subscription, per_seat |
| price_cents | int64 | Price in cents (0 for free) |
| currency | string | ISO 4217 currency code |
| status | enum | draft, pending_review, published, archived |
| metadata | jsonb | App-specific metadata |
| created_at | timestamp | Creation time |
| updated_at | timestamp | Last update time |

#### License

A license grants access to a product for an organization.

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique identifier |
| listing_id | UUID | Associated listing |
| organization_id | UUID | Licensed organization |
| license_type | enum | seat_based, team, unlimited |
| seats | int | Number of seats (null for unlimited) |
| used_seats | int | Currently assigned seats |
| valid_from | timestamp | License start date |
| valid_until | timestamp | License end date (null for perpetual) |
| stripe_subscription_id | string | Stripe subscription (for recurring) |
| purchased_by | UUID | Principal who purchased |
| created_at | timestamp | Creation time |

#### Subscription

Platform-level subscription for an organization.

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique identifier |
| organization_id | UUID | Subscribed organization |
| plan_tier | string | Plan name (free, starter, pro, enterprise) |
| status | enum | active, past_due, canceled, trialing |
| current_period_start | timestamp | Billing period start |
| current_period_end | timestamp | Billing period end |
| stripe_subscription_id | string | Stripe subscription ID |
| stripe_customer_id | string | Stripe customer ID |
| created_at | timestamp | Creation time |

## Pricing Models

### Platform Subscriptions

| Tier | Monthly | Features |
|------|---------|----------|
| **Free** | $0 | Limited features, single user |
| **Starter** | $29 | 5 users, basic features |
| **Pro** | $99 | 25 users, advanced features |
| **Enterprise** | Custom | Unlimited, SSO, support |

### Product Pricing

| Model | Description | Use Case |
|-------|-------------|----------|
| **Free** | No charge, attribution required | Open source, freemium |
| **One-Time** | Single purchase, perpetual access | Simple products |
| **Subscription** | Recurring monthly/annual | Premium content |
| **Per-Seat** | Per-user pricing | Team products |

### Revenue Sharing

| Component | Default Split |
|-----------|---------------|
| Creator | 70% |
| Platform | 30% |

Configurable per application or per listing tier.

## Authorization Integration

### SpiceDB Schema Fragment

```zed
// Shared marketplace definitions for SpiceDB

definition listing {
    relation creator_org: creator_org
    relation owner: principal
    relation licensed_org: consumer_org

    permission manage = owner + creator_org->manage
    permission edit = manage + creator_org->create
    permission publish = creator_org->publish
    permission use = licensed_org->use
    permission view = use + edit
}

definition license {
    relation listing: listing
    relation organization: consumer_org
    relation purchased_by: principal
    relation seat_holder: principal

    permission view = organization->manage + purchased_by
    permission use = seat_holder + organization->use
    permission manage = organization->manage
}

definition subscription {
    relation organization: consumer_org
    relation subscriber: principal

    permission view = organization->view
    permission manage = organization->manage
}
```

### Permission Checks

```go
// Check if user can access a licensed product
authz.Can(ctx, principal, "use", license)

// Check if user can purchase on behalf of org
authz.Can(ctx, principal, "purchase", organization)

// Check if creator can publish listing
authz.Can(ctx, principal, "publish", listing)
```

## Stripe Integration

### Connect Account Setup

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Creator Org    │     │    Platform     │     │     Stripe      │
│                 │     │                 │     │                 │
│  Onboard        │────▶│  Create Connect │────▶│  Connect Acct   │
│                 │     │  Account        │     │                 │
│  Receive        │◀────│  Payout         │◀────│  Transfer       │
│  Revenue        │     │  (70%)          │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Webhook Events

| Event | Handler Action |
|-------|----------------|
| `checkout.session.completed` | Create License, sync to SpiceDB |
| `customer.subscription.updated` | Update License validity |
| `customer.subscription.deleted` | Revoke License, sync to SpiceDB |
| `invoice.payment_failed` | Mark License as past_due |
| `account.updated` | Update Connect account status |

## API Endpoints

### Listings

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/marketplace/listings` | Browse listings |
| GET | `/api/v1/marketplace/listings/{id}` | Get listing details |
| POST | `/api/v1/creators/{orgId}/listings` | Create listing (creator) |
| PATCH | `/api/v1/creators/{orgId}/listings/{id}` | Update listing |
| POST | `/api/v1/creators/{orgId}/listings/{id}/publish` | Publish listing |

### Licenses

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/organizations/{orgId}/licenses` | List org licenses |
| POST | `/api/v1/organizations/{orgId}/licenses` | Purchase license |
| GET | `/api/v1/organizations/{orgId}/licenses/{id}` | Get license details |
| POST | `/api/v1/organizations/{orgId}/licenses/{id}/assign` | Assign seat |
| DELETE | `/api/v1/organizations/{orgId}/licenses/{id}/assign/{userId}` | Unassign seat |

### Subscriptions

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/organizations/{orgId}/subscription` | Get subscription |
| POST | `/api/v1/organizations/{orgId}/subscription` | Create subscription |
| PATCH | `/api/v1/organizations/{orgId}/subscription` | Update plan |
| DELETE | `/api/v1/organizations/{orgId}/subscription` | Cancel subscription |

### Webhooks

| Method | Path | Description |
|--------|------|-------------|
| POST | `/webhooks/stripe` | Stripe webhook handler |

## Success Metrics

1. **Conversion**: 5% of free users upgrade to paid
2. **Creator Satisfaction**: > 4.5/5 payout experience rating
3. **Latency**: < 100ms license check latency
4. **Revenue**: Track GMV, platform revenue, creator payouts

## Out of Scope (v1)

- Multi-currency pricing (single currency per listing)
- Coupon/discount codes
- Affiliate/referral tracking
- Bundle pricing
- Usage-based pricing
- Crypto payments

## Dependencies

- SystemForge authz module (SpiceDB integration)
- SystemForge identity module (organizations, principals)
- Stripe (payments, Connect)
- PostgreSQL (data storage)

## Implementation Phases

### Phase 1: Core Types (Week 1)

- Define Go types for Listing, License, Subscription
- Create Ent schemas
- Define service interfaces

### Phase 2: Licensing Service (Week 2)

- Implement license CRUD
- SpiceDB sync for licenses
- License validation middleware

### Phase 3: Stripe Integration (Week 3)

- Checkout flow
- Webhook handlers
- Connect onboarding

### Phase 4: App Integration (Week 4)

- App1 integration
- App2 integration
- Testing and documentation

## References

- [Stripe Connect Documentation](https://stripe.com/docs/connect)
- [SpiceDB Documentation](https://authzed.com/docs)
- [App1 FEAT_ENTITLEMENTS_PRD.md](../../../app1/docs/design/FEAT_ENTITLEMENTS_PRD.md)
- [App2 AUTHORIZATION.md](../../../app2/docs/design/AUTHORIZATION.md)
