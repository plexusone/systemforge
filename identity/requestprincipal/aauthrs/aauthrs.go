// Package aauthrs authenticates AI agents at a resource server with AAuth
// (draft-hardt-oauth-aauth-protocol), producing a
// requestprincipal.RequestPrincipal.
//
// An AAuth request carries an HTTP message signature (RFC 9421) and, in the
// Signature-Key header, the token binding the signing key: an agent token
// (the agent's identity), a person token (the person the agent acts for,
// from the person's Person Server), or an auth token (an authorization for
// this resource, from a Person Server or Access Server). The Authenticator
// verifies the signature and the token and, depending on the access mode,
// either accepts the request or answers with the AAuth-Requirement
// challenge for the next token:
//
//	no Signature-Key           → next authenticator (or requirement=agent-token)
//	agent token                → requirement=person-token
//	person token               → requirement=auth-token with a resource token
//	auth token, scopes granted → principal (Type agent)
//	auth token, scope missing  → requirement=auth-token (step-up)
//
// Person and auth tokens are accepted only from Config.TrustedIssuers,
// whose keys are discovered through their AAuth metadata and JWKS (cached
// per the draft). An agent's aauth.Transport follows the challenges
// automatically.
//
// This package is the only part of SystemForge that imports
// github.com/aauth-dev/aauth-go.
package aauthrs

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/golang-jwt/jwt/v5"

	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// DefaultJWKSPath is where Register serves the resource's JWKS.
const DefaultJWKSPath = "/.well-known/aauth-resource-jwks.json"

// Config configures an Authenticator.
type Config struct {
	// Resource is this resource server's identifier (https, host only,
	// e.g. "https://api.example.com"): the aud of the person and auth
	// tokens it accepts and the iss of the resource tokens it issues.
	// Required.
	Resource string

	// TrustedIssuers are the Person Servers and Access Servers whose
	// person and auth tokens this resource accepts. Tokens from any other
	// issuer are refused before any key discovery. Required.
	TrustedIssuers []string

	// AccessMode is the credential the resource requires
	// (aauth.AccessMode*): AccessModeAuthToken (the default) serves only
	// auth tokens; AccessModePersonToken also serves person tokens when
	// the route requires no scopes; AccessModeAgentToken also serves bare
	// agent tokens when the route requires no scopes.
	AccessMode string

	// Scopes returns the scopes a request requires. An auth token must
	// grant all of them; a resource token requests them. Nil requires
	// none.
	Scopes func(r *http.Request) []string

	// Key signs resource tokens, and KeyID is its kid (default: the RFC
	// 7638 thumbprint). Required unless AccessMode is
	// AccessModeAgentToken.
	Key   crypto.Signer
	KeyID string

	// Audience, for four-party access, is the resource's Access Server:
	// resource tokens are addressed to it, and it is the only issuer whose
	// auth tokens are accepted (dwk aauth-access.json). Empty means
	// three-party: resource tokens go to the Person Server named by the
	// presented token, and only auth tokens a trusted Person Server issued
	// itself (dwk aauth-person.json) are accepted. Either way a Person
	// Server trusted for person tokens cannot grant itself scopes that
	// bypass the Access Server.
	Audience string

	// Resolver locates person and auth token issuer keys. Default: a
	// JWKS resolver (aauth.JWKSResolver) over HTTPClient and JWKSCache.
	// It is always restricted to TrustedIssuers.
	Resolver aauth.KeyResolver
	// AgentResolver locates agent token keys (AccessModeAgentToken).
	// Default: a JWKS resolver over HTTPClient and JWKSCache.
	AgentResolver aauth.KeyResolver
	// TrustedAgentIssuers, when set, are the only agent providers whose
	// agent tokens this resource accepts; tokens from other issuers are
	// refused before any key discovery. Empty accepts any agent provider.
	// Either way an agent token is accepted only when its agent
	// identifier's domain is its issuer's host, so a provider cannot claim
	// another domain's agents.
	TrustedAgentIssuers []string
	// HTTPClient performs key discovery. Default: aauth.DiscoveryClient,
	// which reaches only public https destinations; a client supplied here
	// should apply the same egress admission. Local development needs a
	// client that can reach the local issuer.
	HTTPClient *http.Client
	// JWKSCache caches discovered key sets. Default: a new cache.
	JWKSCache *aauth.JWKSCache

	// Signature tunes HTTP message signature verification: the validity
	// window, the clock, and components agents must cover beyond the base
	// set. The zero value uses the library defaults. Its Authority
	// defaults to the host of Resource, so a request signed for another
	// server is refused and cannot be replayed here.
	Signature aauth.RequestVerifyOptions

	// CheckSubject is the resource's record check for a person (draft
	// §9.4.3.2): it confirms or establishes the resource's record for
	// (iss, sub). Its error rejects the request.
	CheckSubject func(ctx context.Context, iss, sub string) error

	// Resolve, when set, runs on every accepted request: it may map the
	// principal to an application principal (setting PrincipalID or
	// Organization) or reject the request. Its error is returned from
	// Authenticate unchanged: a *requestprincipal.Error is that response,
	// any other error a 500.
	Resolve func(ctx context.Context, p *requestprincipal.RequestPrincipal) error

	// Limiter, when set, rate-limits resource token issuance per agent
	// key (key "aauth-rs:resource-token:<thumbprint>"); a refusal is a
	// 429 with Retry-After.
	Limiter aauth.Limiter

	// Metadata supplies the display members (name, description, logos,
	// ...) of aauth-resource.json; issuer and jwks_uri are filled in.
	Metadata aauth.ServerMetadata
	// ScopeDescriptions are published in aauth-resource.json for consent
	// screens.
	ScopeDescriptions map[string]string
	// JWKSPath is the path of the resource's JWKS (default
	// DefaultJWKSPath).
	JWKSPath string

	// InsecureSkipIdentifierCheck accepts http and port-bearing
	// identifiers, for development and tests. Never set it in production.
	InsecureSkipIdentifierCheck bool
}

// Authenticator verifies AAuth requests. It implements
// requestprincipal.Authenticator and requestprincipal.Challenger.
type Authenticator struct {
	cfg     Config
	trusted map[string]bool
	verify  aauth.TokenVerifyOptions
	agent   aauth.VerifyAgentTokenOptions
	jwk     aauth.JWK
}

// New validates cfg and returns an Authenticator.
func New(cfg Config) (*Authenticator, error) {
	if cfg.Resource == "" {
		return nil, errors.New("aauthrs: Config.Resource is required")
	}
	if !cfg.InsecureSkipIdentifierCheck {
		if err := aauth.ValidateServerIdentifier(cfg.Resource); err != nil {
			return nil, fmt.Errorf("aauthrs: Config.Resource: %w", err)
		}
	}
	if cfg.Signature.Authority == "" {
		authority, err := aauth.AuthorityOf(cfg.Resource)
		if err != nil {
			return nil, fmt.Errorf("aauthrs: Config.Resource: %w", err)
		}
		cfg.Signature.Authority = authority
	}
	if cfg.Audience != "" && !cfg.InsecureSkipIdentifierCheck {
		if err := aauth.ValidateServerIdentifier(cfg.Audience); err != nil {
			return nil, fmt.Errorf("aauthrs: Config.Audience: %w", err)
		}
	}
	switch cfg.AccessMode {
	case "":
		cfg.AccessMode = aauth.AccessModeAuthToken
	case aauth.AccessModeAuthToken, aauth.AccessModePersonToken, aauth.AccessModeAgentToken:
	default:
		return nil, fmt.Errorf("aauthrs: unsupported access mode %q", cfg.AccessMode)
	}
	if len(cfg.TrustedIssuers) == 0 && cfg.AccessMode != aauth.AccessModeAgentToken {
		return nil, errors.New("aauthrs: Config.TrustedIssuers is required")
	}
	trusted := make(map[string]bool, len(cfg.TrustedIssuers))
	for _, iss := range cfg.TrustedIssuers {
		if !cfg.InsecureSkipIdentifierCheck {
			if err := aauth.ValidateServerIdentifier(iss); err != nil {
				return nil, fmt.Errorf("aauthrs: trusted issuer %q: %w", iss, err)
			}
		}
		trusted[iss] = true
	}
	a := &Authenticator{cfg: cfg, trusted: trusted}
	if cfg.Key != nil {
		jwk, err := aauth.NewJWK(cfg.Key.Public())
		if err != nil {
			return nil, fmt.Errorf("aauthrs: Config.Key: %w", err)
		}
		if cfg.KeyID != "" {
			jwk.Kid = cfg.KeyID
		}
		a.jwk = jwk
	} else if cfg.AccessMode != aauth.AccessModeAgentToken {
		return nil, errors.New("aauthrs: Config.Key is required to issue resource tokens")
	}
	if a.cfg.JWKSPath == "" {
		a.cfg.JWKSPath = DefaultJWKSPath
	}
	cache := cfg.JWKSCache
	if cache == nil {
		cache = &aauth.JWKSCache{}
	}
	discovery := aauth.JWKSResolver{HTTPClient: cfg.HTTPClient, Cache: cache}
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = discovery
	}
	agentResolver := cfg.AgentResolver
	if agentResolver == nil {
		agentResolver = discovery
	}
	// The Access Server's keys are resolvable too: it issues the auth
	// tokens in four-party, without being trusted for person tokens.
	resolvable := trusted
	if cfg.Audience != "" && !trusted[cfg.Audience] {
		resolvable = make(map[string]bool, len(trusted)+1)
		for iss := range trusted {
			resolvable[iss] = true
		}
		resolvable[cfg.Audience] = true
	}
	a.verify = aauth.TokenVerifyOptions{
		Resolver:                    trustedResolver{next: resolver, trusted: resolvable},
		Signature:                   cfg.Signature,
		InsecureSkipIdentifierCheck: cfg.InsecureSkipIdentifierCheck,
	}
	if len(cfg.TrustedAgentIssuers) > 0 {
		agentTrusted := make(map[string]bool, len(cfg.TrustedAgentIssuers))
		for _, iss := range cfg.TrustedAgentIssuers {
			if !cfg.InsecureSkipIdentifierCheck {
				if err := aauth.ValidateServerIdentifier(iss); err != nil {
					return nil, fmt.Errorf("aauthrs: trusted agent issuer %q: %w", iss, err)
				}
			}
			agentTrusted[iss] = true
		}
		agentResolver = trustedResolver{next: agentResolver, trusted: agentTrusted}
	}
	a.agent = aauth.VerifyAgentTokenOptions{
		Resolver:              agentResolver,
		RequireProviderClaims: !cfg.InsecureSkipIdentifierCheck,
		Signature:             cfg.Signature,
	}
	return a, nil
}

// Challenge implements requestprincipal.Challenger: requirement=agent-token
// (draft §6.1) and a Link to the resource metadata (§11.2.5).
func (a *Authenticator) Challenge(h http.Header) {
	h.Set(aauth.HeaderRequirement, aauth.Requirement{Requirement: aauth.RequirementAgentToken}.String())
	h.Add("Link", aauth.ResourceMetadataLink(a.cfg.Resource))
}

// Authenticate implements requestprincipal.Authenticator. A request with
// no Signature-Key header is left to the next authenticator.
func (a *Authenticator) Authenticate(r *http.Request) (*requestprincipal.RequestPrincipal, error) {
	if r.Header.Get("Signature-Key") == "" {
		return nil, requestprincipal.ErrNoCredentials
	}
	tok, err := aauth.ParseSignatureKey(r)
	if err != nil {
		return nil, signatureFailure(err)
	}
	typ, err := aauth.TokenType(tok)
	if err != nil {
		return nil, signatureFailure(err)
	}
	var required []string
	if a.cfg.Scopes != nil {
		required = a.cfg.Scopes(r)
	}
	switch typ {
	case aauth.TypAuth:
		return a.authToken(r, required)
	case aauth.TypPerson:
		return a.personToken(r, required)
	case aauth.TypAgent:
		return a.agentToken(r, required)
	}
	return nil, signatureFailure(fmt.Errorf("%w: unexpected token typ %q", aauth.ErrWrongTokenType, typ))
}

func (a *Authenticator) authToken(r *http.Request, required []string) (*requestprincipal.RequestPrincipal, error) {
	ctx := r.Context()
	claims, err := aauth.VerifyAndExtractAuth(ctx, r, a.cfg.Resource, aauth.AuthTokenVerifyOptions{
		TokenVerifyOptions: a.verify,
		CheckSubject:       a.cfg.CheckSubject,
	})
	if err != nil {
		return nil, signatureFailure(err)
	}
	if err := a.trustAuth(claims.Issuer, claims.DWK); err != nil {
		return nil, signatureFailure(err)
	}
	if missing := missingScopes(required, strings.Fields(claims.Scope)); len(missing) > 0 {
		// Step-up: a resource token against the verified auth token
		// requests the full scope (draft §6.5, §6.7).
		return nil, a.challengeAuthToken(ctx, claims, required)
	}
	p := &requestprincipal.RequestPrincipal{
		PrincipalID:  PrincipalID(claims.PS, claims.Subject),
		Type:         requestprincipal.TypeAgent,
		Subject:      claims.Subject,
		Organization: claims.Tenant,
		Actor:        "jkt:" + claims.Cnf.JWK.Thumbprint(),
		Delegator:    PrincipalID(claims.PS, claims.Subject),
		Mission:      claims.MissionS256,
		Session:      claims.ID,
		Protocol:     requestprincipal.ProtocolAAuth,
		Scopes:       strings.Fields(claims.Scope),
		Proof:        a.proof(r, aauth.TypAuth, claims.Issuer, claims.ID, claims.Cnf.JWK, claims.IssuedAt, claims.ExpiresAt),
		Claims:       map[string]any{"ps": claims.PS, "dwk": claims.DWK},
		Native:       claims,
	}
	if claims.Account != "" {
		p.Claims["account"] = claims.Account
	}
	return a.resolve(ctx, p)
}

func (a *Authenticator) personToken(r *http.Request, required []string) (*requestprincipal.RequestPrincipal, error) {
	ctx := r.Context()
	claims, err := aauth.VerifyAndExtractPerson(ctx, r, a.cfg.Resource, a.verify)
	if err != nil {
		return nil, signatureFailure(err)
	}
	if !a.trusted[claims.Issuer] {
		return nil, signatureFailure(untrusted(claims.Issuer))
	}
	if a.cfg.AccessMode == aauth.AccessModeAuthToken || len(required) > 0 {
		return nil, a.challengeAuthToken(ctx, claims, required)
	}
	if a.cfg.CheckSubject != nil {
		if err := a.cfg.CheckSubject(ctx, claims.Issuer, claims.Subject); err != nil {
			return nil, signatureFailure(err)
		}
	}
	id := PrincipalID(claims.Issuer, claims.Subject)
	p := &requestprincipal.RequestPrincipal{
		PrincipalID:  id,
		Type:         requestprincipal.TypeAgent,
		Subject:      claims.Subject,
		Organization: claims.Tenant,
		Actor:        "jkt:" + claims.Cnf.JWK.Thumbprint(),
		Delegator:    id,
		Mission:      claims.MissionS256,
		Session:      claims.ID,
		Protocol:     requestprincipal.ProtocolAAuth,
		Proof:        a.proof(r, aauth.TypPerson, claims.Issuer, claims.ID, claims.Cnf.JWK, claims.IssuedAt, claims.ExpiresAt),
		Claims:       map[string]any{"ps": claims.Issuer, "dwk": claims.DWK},
		Native:       claims,
	}
	return a.resolve(ctx, p)
}

func (a *Authenticator) agentToken(r *http.Request, required []string) (*requestprincipal.RequestPrincipal, error) {
	if a.cfg.AccessMode != aauth.AccessModeAgentToken || len(required) > 0 {
		// The person the agent acts for comes first (draft §6.4).
		return nil, &requestprincipal.Error{
			Status:  http.StatusUnauthorized,
			Respond: aauth.ChallengePersonToken,
			Message: "person token required",
		}
	}
	ctx := r.Context()
	claims, err := aauth.VerifyAndExtractAgent(ctx, r, a.agent)
	if err != nil {
		return nil, signatureFailure(err)
	}
	if !a.cfg.InsecureSkipIdentifierCheck {
		if err := agentBelongsToIssuer(claims.Subject, claims.Issuer); err != nil {
			return nil, signatureFailure(err)
		}
	}
	p := &requestprincipal.RequestPrincipal{
		PrincipalID: claims.Subject,
		Type:        requestprincipal.TypeAgent,
		Subject:     claims.Subject,
		Actor:       claims.Subject,
		Session:     claims.ID,
		Protocol:    requestprincipal.ProtocolAAuth,
		Proof:       a.proof(r, aauth.TypAgent, claims.Issuer, claims.ID, claims.Cnf.JWK, claims.IssuedAt, claims.ExpiresAt),
		Claims:      map[string]any{"dwk": claims.DWK},
		Native:      claims,
	}
	if claims.PS != "" {
		p.Claims["ps"] = claims.PS
	}
	if claims.ParentAgent != "" {
		p.Claims["parent_agent"] = claims.ParentAgent
	}
	return a.resolve(ctx, p)
}

// challengeAuthToken issues a resource token against the verified
// presented token and answers requirement=auth-token (draft §6.5).
func (a *Authenticator) challengeAuthToken(ctx context.Context, presented aauth.PresentedToken, scopes []string) error {
	if a.cfg.Key == nil {
		return &requestprincipal.Error{
			Status:  http.StatusForbidden,
			Code:    "INSUFFICIENT_SCOPE",
			Message: "the credential does not grant the required scope",
		}
	}
	if a.cfg.Limiter != nil {
		key := "aauth-rs:resource-token:" + presentedThumbprint(presented)
		if ok, retry := a.cfg.Limiter.Allow(ctx, key); !ok {
			secs := int((retry + time.Second - 1) / time.Second)
			return &requestprincipal.Error{
				Status:  http.StatusTooManyRequests,
				Header:  http.Header{"Retry-After": {fmt.Sprint(secs)}},
				Code:    "RATE_LIMITED",
				Message: "too many authorization requests",
			}
		}
	}
	rt, err := aauth.IssueResourceToken(aauth.ResourceTokenParams{
		Resource: a.cfg.Resource,
		Audience: a.cfg.Audience,
		Scope:    strings.Join(scopes, " "),
		Now:      a.now(),
	}, presented, a.cfg.Key, a.jwk.Kid)
	if err != nil {
		return fmt.Errorf("aauthrs: issuing resource token: %w", err)
	}
	return &requestprincipal.Error{
		Status:  http.StatusUnauthorized,
		Respond: func(w http.ResponseWriter) { aauth.ChallengeAuthToken(w, rt) },
		Message: "auth token required",
	}
}

func (a *Authenticator) resolve(ctx context.Context, p *requestprincipal.RequestPrincipal) (*requestprincipal.RequestPrincipal, error) {
	if a.cfg.Resolve != nil {
		if err := a.cfg.Resolve(ctx, p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (a *Authenticator) now() time.Time {
	if a.cfg.Signature.Now != nil {
		return a.cfg.Signature.Now()
	}
	return time.Now()
}

func (a *Authenticator) proof(r *http.Request, method, iss, jti string, cnf *aauth.JWK, iat, exp *jwt.NumericDate) requestprincipal.Proof {
	p := requestprincipal.Proof{
		Method:  method,
		Issuer:  iss,
		TokenID: jti,
		Params: map[string]string{
			"signature_input": r.Header.Get("Signature-Input"),
		},
	}
	if method != aauth.TypAgent {
		p.Audience = a.cfg.Resource
	}
	if cnf != nil {
		p.KeyThumbprint = cnf.Thumbprint()
	}
	if iat != nil {
		p.IssuedAt = iat.Time
	}
	if exp != nil {
		p.ExpiresAt = exp.Time
	}
	return p
}

// PrincipalID is the PrincipalID this package assigns to the person an
// agent acts for: the person's Person Server and its subject identifier
// for this resource, "<ps>#<sub>". A Person Server's sub is directed (it
// differs per resource) and unique within that server only.
func PrincipalID(ps, sub string) string { return ps + "#" + sub }

// signatureFailure answers 401 with the Signature-Error the library
// prescribes for err.
func signatureFailure(err error) error {
	return &requestprincipal.Error{
		Status:  http.StatusUnauthorized,
		Respond: func(w http.ResponseWriter) { aauth.WriteSignatureFailure(w, err) },
		Message: "invalid AAuth credentials",
		Err:     err,
	}
}

// agentBelongsToIssuer checks that an agent identifier's domain is the
// host of the agent provider that issued its token. Agent token keys are
// discovered from the issuer the token names, so without this check any
// provider could issue tokens for another domain's agents.
func agentBelongsToIssuer(sub, iss string) error {
	id, err := aauth.ParseAgentIdentifier(sub)
	if err != nil {
		return fmt.Errorf("%w: %w", aauth.ErrInvalidToken, err)
	}
	u, err := url.Parse(iss)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("%w: agent token issuer %q is not a URL", aauth.ErrInvalidToken, iss)
	}
	if !strings.EqualFold(id.Domain, u.Hostname()) {
		return fmt.Errorf("%w: agent %q is not an agent of issuer %q", aauth.ErrInvalidToken, sub, iss)
	}
	return nil
}

// trustAuth decides who may issue an auth token (draft §9.4, §13): in
// four-party only the resource's Access Server, in three-party only a
// trusted Person Server issuing for itself. Without this, a Person Server
// trusted for person tokens could mint auth tokens for any scope and
// bypass the Access Server.
func (a *Authenticator) trustAuth(iss, dwk string) error {
	if a.cfg.Audience != "" {
		if iss != a.cfg.Audience || dwk != aauth.WellKnownAccess {
			return fmt.Errorf("%w: %w: this resource accepts auth tokens only from its access server %s",
				aauth.ErrInvalidToken, errUntrustedIssuer, a.cfg.Audience)
		}
		return nil
	}
	if dwk != aauth.WellKnownPerson {
		return fmt.Errorf("%w: %w: this resource accepts auth tokens only from a person server (dwk %s)",
			aauth.ErrInvalidToken, errUntrustedIssuer, aauth.WellKnownPerson)
	}
	if !a.trusted[iss] {
		return untrusted(iss)
	}
	return nil
}

// errUntrustedIssuer marks a token from an issuer outside TrustedIssuers.
var errUntrustedIssuer = errors.New("issuer is not trusted by this resource")

func untrusted(iss string) error {
	return fmt.Errorf("%w: %w: %q", aauth.ErrInvalidToken, errUntrustedIssuer, iss)
}

// trustedResolver refuses issuers outside the allowlist before any key
// discovery, so attacker-chosen issuers are never fetched.
type trustedResolver struct {
	next    aauth.KeyResolver
	trusted map[string]bool
}

func (t trustedResolver) ResolveKey(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error) {
	if !t.trusted[iss] {
		return nil, untrusted(iss)
	}
	return t.next.ResolveKey(ctx, iss, dwk, kid, cnf)
}

func (t trustedResolver) RefreshKey(ctx context.Context, iss, dwk, kid string, cnf *aauth.JWK) (crypto.PublicKey, error) {
	if !t.trusted[iss] {
		return nil, untrusted(iss)
	}
	if rr, ok := t.next.(aauth.KeyRefresher); ok {
		return rr.RefreshKey(ctx, iss, dwk, kid, cnf)
	}
	return t.next.ResolveKey(ctx, iss, dwk, kid, cnf)
}

func missingScopes(required, granted []string) []string {
	var missing []string
	for _, s := range required {
		if !slices.Contains(granted, s) {
			missing = append(missing, s)
		}
	}
	return missing
}

func presentedThumbprint(p aauth.PresentedToken) string {
	switch c := p.(type) {
	case *aauth.PersonClaims:
		if c.Cnf.JWK != nil {
			return c.Cnf.JWK.Thumbprint()
		}
	case *aauth.AuthClaims:
		if c.Cnf.JWK != nil {
			return c.Cnf.JWK.Thumbprint()
		}
	}
	return ""
}

var (
	_ requestprincipal.Authenticator = (*Authenticator)(nil)
	_ requestprincipal.Challenger    = (*Authenticator)(nil)
	_ aauth.KeyRefresher             = trustedResolver{}
)
