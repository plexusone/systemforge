package systemauthsvc

import (
	"context"
	"log/slog"
	"time"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/systemauth"
)

// EventProductionWaiver is the event type of the security event recorded,
// through Options.AuditEmitter, for every production check waived when the
// service starts.
const EventProductionWaiver = "systemauth.production.waiver"

// waiverSingleInstance names the DPoP replay-cache waiver in the waiver
// event: the configuration's dpop.single_instance.
const waiverSingleInstance = "dpop.single_instance"

// waiverRisks says, for the startup log, what each production waiver
// gives up.
var waiverRisks = map[string]string{
	systemauth.AllowEphemeralHMACSecret:           "refresh tokens and authorization codes stop validating after a restart and on other instances",
	systemauth.AllowClientSecretClientCredentials: "clients get tokens with a shared secret through the client_credentials grant",
	systemauth.AllowBearerTokenClients:            "clients registered with allow_bearer_tokens get tokens not bound to a DPoP key",
	waiverSingleInstance:                          "the DPoP replay cache is per instance, so a proof replayed to another instance is accepted",
}

// productionPolicy logs, and records as security events, every production
// check the configuration waives and returns the option making the token
// endpoint refuse what is not waived. In development mode it returns nil:
// nothing is refused.
func productionPolicy(ctx context.Context, c *Config, opts Options, logger *slog.Logger) []systemauth.Option {
	if opts.Dev {
		return nil
	}
	for _, name := range c.Production.Allow {
		logger.Warn("production check waived", "check", name, "setting", "production.allow", "risk", waiverRisks[name])
		emitWaiver(ctx, opts.AuditEmitter, logger, name, "production.allow")
	}
	if c.DPoP.SingleInstance && c.DPoP.ReplayCacheRedisURL == "" && opts.DPoPReplayCache == nil {
		logger.Warn("DPoP replay cache is per instance (dpop.single_instance); run exactly one instance, or a proof replayed to another instance is accepted")
		emitWaiver(ctx, opts.AuditEmitter, logger, waiverSingleInstance, waiverSingleInstance)
	}
	if !rateLimitsShared(c, opts) {
		logger.Warn("rate limit counters are kept per instance; set rate_limit.redis_url when several instances serve SystemAuth, or declare one instance (rate_limit.single_instance or dpop.single_instance)")
	}
	return []systemauth.Option{systemauth.WithProductionPolicy(systemauth.ProductionPolicy{
		RefuseClientSecretClientCredentials: !c.Production.Allows(systemauth.AllowClientSecretClientCredentials),
		RefuseBearerTokenClients:            !c.Production.Allows(systemauth.AllowBearerTokenClients),
	})}
}

// emitWaiver records the waiver of check, named by setting in the
// configuration. Startup continues whether or not it is recorded, so a
// failure is logged.
func emitWaiver(ctx context.Context, e audit.Emitter, logger *slog.Logger, check, setting string) {
	if e == nil {
		return
	}
	ev := &audit.Event{
		Timestamp: time.Now().UTC(),
		EventType: EventProductionWaiver,
		Action:    "waive",
		Actor:     audit.Actor{Type: "service", Identifier: "systemauth"},
		Resource:  audit.Resource{Type: "production_check", Identifier: check},
		Outcome:   audit.OutcomeSuccess,
		Details:   map[string]any{"check": check, "setting": setting, "risk": waiverRisks[check]},
	}
	if err := e.Emit(ctx, ev); err != nil {
		logger.ErrorContext(ctx, "recording production waiver", "check", check, "error", err.Error())
	}
}
