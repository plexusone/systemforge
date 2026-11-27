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

| Type | `CheckPrincipal` grants access to | Seat limit on application roles |
|---|---|---|
| `LicenseUnlimited` | Everyone in the licensed organization | None |
| `LicenseSeatBased` | Principals assigned a seat | The license's seats |
| `LicenseTeam` | Principals assigned a seat | None |

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
// Check if user has access: an unlimited license of an organization they
// belong to (an active membership, or for a non-human principal the
// organization that owns it), or a seat assignment
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
assignment and member removal change it.

`AssignSeat` does not check that the principal belongs to the licensed
organization. The marketplace API's assign endpoint does; code that calls the
service directly must check it.

### Assign a Seat

```go
err := licenseSvc.AssignSeat(ctx, &marketplace.SeatAssignment{
    ID:          uuid.New(),
    LicenseID:   license.ID,
    PrincipalID: userID,
    AssignedBy:  adminID,
})
```

### Unassign a Seat

```go
err := licenseSvc.UnassignSeat(ctx, license.ID, userID)
```

### List Assignments

```go
assignments, err := licenseSvc.ListSeatAssignments(ctx, license.ID)
for _, a := range assignments {
    fmt.Printf("User %s assigned at %s\n", a.PrincipalID, a.AssignedAt)
}
```

### Check Available Seats

```go
license, err := licenseSvc.Get(ctx, licenseID)
if err == nil && !license.HasAvailableSeats() {
    // No seats available, show upgrade prompt
}
```

### When a Member Leaves

`organization.Service.RemoveMember` releases the member's seats on that
organization's licenses in the same transaction. Seats they hold on other
organizations' licenses stay.

These do not release seats, so unassign them yourself:

- revoking a collaborator's last resource grant, which removes the membership
- deleting a service account
- removals made before this behavior existed

## Using SpiceDB

The database and the authorization graph are updated separately. If a
deployment writes marketplace relationships to SpiceDB, give the same syncer to
every service that changes them:

```go
syncer := marketplace.NewSpiceDBSyncer(spice)

// Writes listings, licenses and seats.
market := marketplace.NewEntService(client, syncer)

// Removes a removed member's seats.
orgs := organization.NewService(client,
    organization.WithSeatSyncer(syncer),
)
```

Paid licenses granted by billing are written by the billing sink; see
`billing.WithAuthzSyncer`.

Without `WithSeatSyncer`, removal releases seats in the database only, and the
`seat_holder` relationships keep granting `use` on the license in the graph.
Check every place that builds an organization service, including SCIM
provisioning: the SCIM setup in `systemauthsvc` does not set a seat syncer.

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
