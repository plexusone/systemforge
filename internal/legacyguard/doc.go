// Package legacyguard holds a repository-wide test that keeps retired names
// from returning: the legacy identity model (ADR-004), the Core-era names
// coreauth, corecontrol, core_control, core_auth and the cf_ prefix
// (ADR-001), and upstream GitHub/Google OAuth endpoint wiring outside
// identity/oauthclient. It has no runtime code.
package legacyguard
