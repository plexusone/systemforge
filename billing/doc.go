// Package billing connects SystemForge to payforge
// (github.com/plexusone/payforge), which turns a pricing spec into products
// and prices at a payment provider and a paid subscription into an
// entitlement. It supplies the ports payforge leaves to the host, backed by
// the SystemForge Ent client.
//
// It is a package of its own, not part of marketplace, because it serves
// both the organization's platform plan and marketplace listings, and
// because marketplace stays free of any payment provider: billing depends
// on marketplace, never the reverse.
//
// # The subject
//
// The subject payforge bills is the buying organization: payforge's
// Subject.ID and Entitlement.Subject are an organization ID.
//
// # Pieces
//
//   - [Store] is payforge's Store: processed event IDs, kept with a unique
//     constraint so an event is applied once across instances, and the
//     mapping from a provider customer to an organization.
//   - billing/pglock is a payforge.Locker that holds across instances with
//     a PostgreSQL advisory lock; payforge.MemoryLocker holds within one
//     process.
//
// The tables are created by the Ent schema migration (Schema.Create, or
// systemauth migrate); no SQL migration is needed.
package billing
