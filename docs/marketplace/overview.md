# Marketplace

SystemForge provides a SaaS marketplace infrastructure with Stripe integration for subscription billing, license management, and seat-based access control.

## Features

- **Listings** - Product catalog with multiple tiers and pricing
- **Subscriptions** - Stripe-powered recurring billing
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
import (
    "github.com/plexusone/systemforge/marketplace"
    "github.com/plexusone/systemforge/marketplace/stripe"
)

// Create services with Ent client
listingSvc := marketplace.NewEntListingService(entClient, nil)
licenseSvc := marketplace.NewEntLicenseService(entClient, nil)
seatSvc := marketplace.NewEntSeatAssignmentService(entClient, nil)
subSvc := marketplace.NewEntSubscriptionService(entClient, nil)

// Create Stripe checkout service
checkoutSvc := stripe.NewCheckoutService(stripe.Config{
    SecretKey:     os.Getenv("STRIPE_SECRET_KEY"),
    WebhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
    SuccessURL:    "https://app.example.com/checkout/success",
    CancelURL:     "https://app.example.com/checkout/cancel",
}, licenseSvc, subSvc)
```

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

### 3. Handle Checkout

```go
// Create Stripe checkout session
session, err := checkoutSvc.CreateCheckoutSession(ctx, stripe.CheckoutRequest{
    ListingID:      listing.ID,
    OrganizationID: orgID,
    PrincipalID:    userID,
    Quantity:       1,
})

// Redirect user to session.URL
http.Redirect(w, r, session.URL, http.StatusSeeOther)
```

### 4. Handle Webhooks

```go
// In your webhook handler
func handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
    payload, _ := io.ReadAll(r.Body)
    signature := r.Header.Get("Stripe-Signature")

    err := checkoutSvc.HandleWebhook(r.Context(), payload, signature)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusOK)
}
```

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
| `LicenseType` | string | Type (unlimited, per_seat, trial) |
| `Seats` | *int | Seat limit (nil = unlimited) |
| `ValidFrom` | time.Time | Start date |
| `ValidUntil` | *time.Time | Expiry date (nil = perpetual) |
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

## Stripe Integration

### Environment Variables

```bash
STRIPE_SECRET_KEY=sk_live_...      # Stripe secret key
STRIPE_WEBHOOK_SECRET=whsec_...    # Webhook signing secret
STRIPE_PUBLISHABLE_KEY=pk_live_... # For frontend (optional)
```

The webhook signing secret is required: with an empty `WebhookSecret`,
`ProcessWebhook` and `VerifyWebhook` refuse every event with
`stripe.ErrWebhookSecretRequired`, because a signature made with an empty key
can be computed by anyone.

### Webhook Events

The checkout service handles these Stripe events:

| Event | Action |
|-------|--------|
| `checkout.session.completed` | Create license and subscription |
| `customer.subscription.updated` | Update license status |
| `customer.subscription.deleted` | Revoke license |
| `invoice.paid` | Extend license validity |
| `invoice.payment_failed` | Mark license as past_due |

### Webhook Endpoint

Register your webhook endpoint in Stripe Dashboard:

```
https://api.example.com/webhooks/stripe
```

Select events:
- `checkout.session.completed`
- `customer.subscription.*`
- `invoice.paid`
- `invoice.payment_failed`

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

The marketplace creates these Ent entities (prefixed with `cf_`):

| Table | Description |
|-------|-------------|
| `sf_listings` | Product listings |
| `sf_licenses` | Organization licenses |
| `sf_subscriptions` | Stripe subscription links |
| `sf_seat_assignments` | User seat assignments |

## Example: Full Purchase Flow

```go
// 1. User selects a plan
listing, _ := listingSvc.Get(ctx, listingID)

// 2. Create checkout session
session, _ := checkoutSvc.CreateCheckoutSession(ctx, stripe.CheckoutRequest{
    ListingID:      listing.ID,
    OrganizationID: orgID,
    PrincipalID:    userID,
    Quantity:       1,
})

// 3. User completes payment on Stripe
// ... redirect to session.URL ...

// 4. Webhook creates license automatically
// checkout.session.completed → license created

// 5. Check access in your app
hasAccess, _ := licenseSvc.CheckPrincipal(ctx, listingID, userID)
// hasAccess = true

// 6. For per-seat licenses, assign seats
if license.LicenseType == marketplace.LicensePerSeat {
    seatSvc.Assign(ctx, &marketplace.SeatAssignment{
        LicenseID:   license.ID,
        PrincipalID: teammateID,
        AssignedBy:  userID,
    })
}
```

## Next Steps

- [Stripe Documentation](https://stripe.com/docs) - Stripe API reference
- [Observability](../observability/overview.md) - Monitor marketplace metrics
- [Authorization](../authorization/integration.md) - Integrate with SpiceDB for access control
