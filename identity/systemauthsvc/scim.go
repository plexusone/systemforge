package systemauthsvc

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/scimtoken"
	"github.com/plexusone/systemforge/identity/scim/store"
)

// SCIMPath is where SystemAuth serves SCIM 2.0 when Options.SCIM is set.
const SCIMPath = "/scim/v2"

// SCIMTokensScope is the access-token scope the SCIM token management API
// (scimtoken.NewAPI, served under /api/v1/organizations/{slug}/scim-tokens)
// requires. The caller must also be an owner or admin of the organization,
// or a platform administrator.
const SCIMTokensScope = "systemforge:scim_tokens"

// SCIMOptions enable SCIM provisioning (identity/scim) at SCIMPath. By
// default a request authenticates with a tenant SCIM token from the
// built-in store (identity/scim/scimtoken) and provisions only that
// token's organization. Platform-wide credentials are accepted only when
// PlatformCredential is set.
type SCIMOptions struct {
	// Config is the SCIM provider configuration. Default:
	// scim.DefaultConfig(). Its BaseURL is always SCIMPath.
	Config *scim.Config

	// Store configures the Ent store. Default: memberships, principals and
	// deleted users changed through the organization and principal services
	// and the store with the authorization mode's syncer. Its BaseURL is always
	// SCIMPath.
	Store *store.Config

	// Authorizer decides who may issue, rotate, revoke and list an
	// organization's SCIM tokens (authz.PermOrgSettings, or platform
	// administration). Default: the configured authorization mode's
	// provider, with platform administrators read from the database in
	// mode rbac.
	Authorizer authz.Authorizer

	// PlatformCredential authenticates platform operator credentials,
	// which provision every organization. It is consulted only for bearer
	// tokens that are not tenant SCIM tokens and must return a credential
	// with scim.Scope.Platform set. Nil, the default, accepts tenant tokens
	// only.
	PlatformCredential func(r *http.Request) (scim.Credential, error)

	// TokenOptions are passed to scimtoken.New after the logger, audit
	// emitter and authorizer New sets.
	TokenOptions []scimtoken.Option

	// ProviderOptions are passed to scim.NewProvider after the scoped
	// authorization hook New sets.
	ProviderOptions []scim.ProviderOption
}

// openSCIM serves SCIM and the token management API when Options.SCIM is
// set.
func (s *Service) openSCIM(opts Options) error {
	so := opts.SCIM
	if so == nil {
		return nil
	}
	if s.client == nil || s.authz == nil {
		return errors.New("systemauthsvc: SCIM needs a database")
	}
	res := s.authz
	authorizer := so.Authorizer
	if authorizer == nil {
		authorizer = res.Provider
	}

	tokOpts := []scimtoken.Option{scimtoken.WithLogger(s.logger), scimtoken.WithAuthorizer(authorizer), scimtoken.WithClientAddress(s.server.ClientAddress())}
	if opts.AuditEmitter != nil {
		tokOpts = append(tokOpts, scimtoken.WithAuditEmitter(opts.AuditEmitter))
	}
	s.scimTokens = scimtoken.New(s.client, append(tokOpts, so.TokenOptions...)...)

	scimCfg := scim.DefaultConfig()
	if so.Config != nil {
		cp := *so.Config
		scimCfg = &cp
	}
	scimCfg.BaseURL = SCIMPath
	storeCfg := store.DefaultConfig()
	if so.Store != nil {
		cp := *so.Store
		storeCfg = &cp
	}
	storeCfg.BaseURL = SCIMPath
	orgs := organization.NewService(s.client,
		organization.WithAuthzSyncer(res.Syncer), organization.WithSyncMode(res.SyncMode), organization.WithLogger(s.logger))
	if storeCfg.Memberships == nil {
		storeCfg.Memberships = orgs
	}
	if storeCfg.Principals == nil {
		storeCfg.Principals = principal.NewService(s.client,
			principal.WithAuthzSyncer(res.Syncer), principal.WithSyncMode(res.SyncMode), principal.WithLogger(s.logger))
	}
	if storeCfg.Syncer == nil {
		storeCfg.Syncer = res.Syncer
	}
	provOpts := append([]scim.ProviderOption{scim.WithAuthorizationHook(scim.NewScopedAuthorizationHook(true))}, so.ProviderOptions...)
	provider, err := scim.NewProvider(scimCfg, store.NewEntStore(s.client, storeCfg), provOpts...)
	if err != nil {
		return fmt.Errorf("systemauthsvc: SCIM provider: %w", err)
	}
	api, err := scim.NewAPI(provider, scim.WithLogger(s.logger))
	if err != nil {
		return fmt.Errorf("systemauthsvc: SCIM API: %w", err)
	}
	cred := s.scimTokens.CredentialFunc(scimtoken.CredentialOptions{Platform: so.PlatformCredential})
	h := noStore(api.CredentialMiddleware(cred)(api))
	router := s.server.Router()
	router.Handle(SCIMPath, h)
	router.Handle(SCIMPath+"/*", h)

	mgmt, err := scimtoken.NewAPI(s.scimTokens, scimtoken.APIConfig{Organizations: orgs, Logger: s.logger})
	if err != nil {
		return fmt.Errorf("systemauthsvc: SCIM token API: %w", err)
	}
	auth := requestprincipal.Middleware(requestprincipal.Options{Logger: s.logger},
		s.server.BearerAuthenticator(SCIMTokensScope))
	mh := auth(mgmt)
	router.Handle("/api/v1/organizations/{slug}/scim-tokens", mh)
	router.Handle("/api/v1/organizations/{slug}/scim-tokens/*", mh)
	s.logger.Info("SCIM enabled", "path", SCIMPath, "platform_credentials", so.PlatformCredential != nil)
	return nil
}

// isPlatformAdmin reads a human's platform administrator flag.
func (s *Service) isPlatformAdmin(ctx context.Context, principalID uuid.UUID) (bool, error) {
	return s.client.Human.Query().
		Where(human.PrincipalID(principalID), human.IsPlatformAdmin(true)).
		Exist(ctx)
}

// SCIMTokens returns the tenant SCIM token store, or nil when Options.SCIM
// is not set. Operator commands and host applications use it to issue,
// rotate and revoke an organization's tokens.
func (s *Service) SCIMTokens() *scimtoken.Service { return s.scimTokens }
