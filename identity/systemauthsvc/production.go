package systemauthsvc

import (
	"log/slog"

	"github.com/plexusone/systemforge/identity/systemauth"
)

// waiverRisks says, for the startup log, what each production waiver
// gives up.
var waiverRisks = map[string]string{
	systemauth.AllowEphemeralHMACSecret:           "refresh tokens and authorization codes stop validating after a restart and on other instances",
	systemauth.AllowClientSecretClientCredentials: "clients get tokens with a shared secret through the client_credentials grant",
	systemauth.AllowBearerTokenClients:            "clients registered with allow_bearer_tokens get tokens not bound to a DPoP key",
}

// productionPolicy logs every production check the configuration waives
// and returns the option making the token endpoint refuse what is not
// waived. In development mode it returns nil: nothing is refused.
func productionPolicy(c *Config, opts Options, logger *slog.Logger) []systemauth.Option {
	if opts.Dev {
		return nil
	}
	for _, name := range c.Production.Allow {
		logger.Warn("production check waived", "check", name, "setting", "production.allow", "risk", waiverRisks[name])
	}
	if c.DPoP.SingleInstance && c.DPoP.ReplayCacheRedisURL == "" && opts.DPoPReplayCache == nil {
		logger.Warn("DPoP replay cache is per instance (dpop.single_instance); run exactly one instance, or a proof replayed to another instance is accepted")
	}
	return []systemauth.Option{systemauth.WithProductionPolicy(systemauth.ProductionPolicy{
		RefuseClientSecretClientCredentials: !c.Production.Allows(systemauth.AllowClientSecretClientCredentials),
		RefuseBearerTokenClients:            !c.Production.Allows(systemauth.AllowBearerTokenClients),
	})}
}
