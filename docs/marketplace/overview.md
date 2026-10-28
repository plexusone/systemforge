# Marketplace

SystemForge provides a SaaS marketplace infrastructure: listings, license management and seat-based access control. Payments are taken by package `billing`, on [payforge](https://github.com/plexusone/payforge); see [Billing](billing.md).

## Features

- **Listings** - Product catalog with multiple tiers and pricing
- **Subscriptions** - The organization's plan, kept up to date by [billing](billing.md)
- **Licenses** - Flexible licensing models (unlimited, per-seat, time-limited)
- **Seat Management** - Assign and revoke user access to subscriptions

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Your Application                             │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────────────┐
│                    Marketplace Package                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐   │
│  │  Listings   │  │  Licenses   │  │  Seat Assignments       │   │
│  │  (Products) │  │  (Grants)   │  │  (User Access)          │   │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘   │
└───────────────────────────┬───────────────────────────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────────────┐
│                    Stripe Integration                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐   │
│  │  Checkout   │  │  Webhooks   │  │  Subscriptions          │   │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘   │
└───────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Create Services

```go
import "github.com/plexusone/systemforge/marketplace"

// Create services with Ent client
listingSvc := marketplace.NewEntListingService(entClient, nil)
licenseSvc := marketplace.NewEntLicenseService(entClient, nil)
subSvc := marketplace.NewEntSubscriptionService(entClient)
```

Checkout, the customer portal and the payment webhook are wired with package
`billing`; see [Billing](billing.md#wiring).

### 2. Create a Listing

```go
listing, err := listingSvc.Create(ctx, &marketplace.Listing{
    ID:          uuid.New(),
    Name:        "Pro Plan",
    Description: "Full access to all features",
    Tier:        marketplace.TierPro,
    PriceCents:  4999, // $49.99/month
    Currency:    "usd",
    IsActive:    true,
})
```

### 3. Take Payments

See [Billing](billing.md): a paid checkout for a listing grants the buying
organization a license, and a full refund or a dispute suspends it.

## Entities

### Listing

Products available in your marketplace.

| Field | Type | Description |
|-------|------|-------------|
| `ID` | UUID | Unique identifier |
| `Name` | string | Display name |
| `Description` | string | Product description |
| `Tier` | string | Tier level (free, starter, pro, enterprise) |
| `PriceCents` | int | Monthly price in cents |
| `Currency` | string | ISO currency code |
| `Features` | []string | Feature list |
| `IsActive` | bool | Whether available for purchase |
| `StripeProductID` | string | Stripe product ID |
| `StripePriceID` | string | Stripe price ID |

### License

Grants access to a listing for an organization.

| Field | Type | Description |
|-------|------|-------------|
| `ID` | UUID | Unique identifier |
| `ListingID` | UUID | Associated listing |
| `OrganizationID` | UUID | Owning organization |
| `LicenseType` | string | Type (`seat_based`, `team`, `unlimited`) |
| `Seats` | *int | Seat limit (nil = unlimited) |
| `ValidFrom` | time.Time | Start date |
| `ValidUntil` | *time.Time | End of validity, exclusive: the license is invalid from this instant on (nil = perpetual) |
| `PurchasedBy` | UUID | Principal who purchased |
| `StripeSubscriptionID` | string | Stripe subscription ID |

### Subscription

Links Stripe subscriptions to licenses.

| Field | Type | Description |
|-------|------|-------------|
| `ID` | UUID | Unique identifier |
| `LicenseID` | UUID | Associated license |
| `StripeSubscriptionID` | string | Stripe subscription ID |
| `StripeCustomerID` | string | Stripe customer ID |
| `Status` | string | Subscription status |
| `CurrentPeriodEnd` | time.Time | Current billing period end |

### SeatAssignment

Assigns users to licensed seats.

| Field | Type | Description |
|-------|------|-------------|
| `ID` | UUID | Unique identifier |
| `LicenseID` | UUID | Associated license |
| `PrincipalID` | UUID | Assigned user |
| `AssignedBy` | UUID | Admin who assigned |
| `AssignedAt` | time.Time | Assignment timestamp |

## License Types

| Type | Description |
|------|-------------|
| `LicenseUnlimited` | Unlimited users, no seat restrictions |
| `LicensePerSeat` | Limited seats, requires seat assignment |
| `LicenseTrial` | Time-limited trial access |
| `LicenseTeam` | Team license with seat limit |
| `LicenseEnterprise` | Enterprise with custom terms |

## Checking Access

### Check Organization License

```go
// Check if organization has valid license for a listing
hasLicense, err := licenseSvc.Check(ctx, listingID, orgID)
if !hasLicense {
    // Redirect to purchase page
}
```

### Check User Access

```go
// Check if user has access (via unlimited license or seat assignment)
hasAccess, err := licenseSvc.CheckPrincipal(ctx, listingID, userID)
if !hasAccess {
    http.Error(w, "No access to this feature", http.StatusForbidden)
    return
}
```

## Seat Management

`EntLicenseService.AssignSeat` reserves a seat with a conditional increment of
the license's used seats in the same transaction as the assignment, so
concurrent assignments cannot exceed the purchased seats, and `UnassignSeat`
releases it the same way. `Update` does not write `UsedSeats`; only seat
assignment changes it.

### Assign a Seat

```go
assignment, err := seatSvc.Assign(ctx, &marketplace.SeatAssignment{
    ID:          uuid.New(),
    LicenseID:   license.ID,
    PrincipalID: userID,
    AssignedBy:  adminID,
    AssignedAt:  time.Now(),
})
```

### Revoke a Seat

```go
err := seatSvc.Revoke(ctx, assignmentID)
```

### List Assignments

```go
assignments, err := seatSvc.ListByLicense(ctx, licenseID)
for _, a := range assignments {
    fmt.Printf("User %s assigned at %s\n", a.PrincipalID, a.AssignedAt)
}
```

### Check Available Seats

```go
available, err := seatSvc.AvailableSeats(ctx, licenseID)
if available <= 0 {
    // No seats available, show upgrade prompt
}
```

## Payments

Payments, webhooks and the customer portal are in package `billing`. See
[Billing](billing.md), including
[upgrading from `marketplace/stripe`](billing.md#upgrading-from-marketplacestripe).

## Listing Tiers

Pre-defined tier constants:

```go
const (
    TierFree       = "free"
    TierStarter    = "starter"
    TierPro        = "pro"
    TierEnterprise = "enterprise"
)
```

## Database Tables

The marketplace creates these Ent entities (prefixed with `sf_`):

| Table | Description |
|-------|-------------|
| `sf_listings` | Product listings |
| `sf_licenses` | Organization licenses |
| `sf_subscriptions` | Organization subscriptions; the one with no listing is the organization's plan |
| `sf_seat_assignments` | User seat assignments |

## Example: Full Purchase Flow

1. The buyer's client calls `POST /billing/checkout/listing` with the
   listing's ID, acting for its organization, and is sent to the returned URL.
2. Stripe reports the paid checkout to `POST /billing/webhook`, and the buying
   organization is granted a license.
3. Your application checks access:

```go
hasAccess, err := licenseSvc.CheckPrincipal(ctx, listingID, userID)
```

## Next Steps

- [Stripe Documentation](https://stripe.com/docs) - Stripe API reference
- [Observability](../observability/overview.md) - Monitor marketplace metrics
- [Authorization](../authorization/integration.md) - Integrate with SpiceDB for access control
