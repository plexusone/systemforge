package aauthrs_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/agentprovider"
	"github.com/aauth-dev/aauth-go/personserver"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/apikey"
	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/identity/requestprincipal/aauthrs"
)

// --- A fake issuer whose tokens the test mints by hand. ---

// fakeIssuer is a Person Server stand-in: it publishes aauth-person.json
// and a JWKS, and the test mints auth tokens with its key.
type fakeIssuer struct {
	url     string
	key     crypto.Signer
	jwk     aauth.JWK
	fetches atomic.Int32
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := aauth.NewJWK(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{key: key, jwk: jwk}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.fetches.Add(1)
		switch r.URL.Path {
		case "/.well-known/" + aauth.WellKnownPerson:
			writeJSON(t, w, map[string]string{"issuer": f.url, "jwks_uri": f.url + "/jwks"})
		case "/jwks":
			writeJSON(t, w, aauth.JWKS{Keys: []aauth.JWK{f.jwk}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

// authToken mints an aa-auth+jwt from f for aud, bound to cnf, granting
// things:read.
func (f *fakeIssuer) authToken(t *testing.T, aud string, cnf aauth.JWK, iat, exp time.Time) string {
	t.Helper()
	tok, err := aauth.MintAuthToken(aauth.AuthClaims{
		DWK:         aauth.WellKnownPerson,
		PS:          f.url,
		Scope:       "things:read",
		MissionS256: "mission-digest",
		Tenant:      "org-1",
		Cnf:         aauth.Cnf{JWK: &cnf},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.url,
			Subject:   "directed-person",
			Audience:  jwt.ClaimStrings{aud},
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(iat),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}, f.key, f.jwk.Kid)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Error(err)
	}
}

// --- The resource server under test. ---

type resourceServer struct {
	url  string
	auth *aauthrs.Authenticator

	mu   sync.Mutex
	last *requestprincipal.RequestPrincipal
}

func (rs *resourceServer) principal() *requestprincipal.RequestPrincipal {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.last
}

type fakeAPIKeys map[string]*apikey.APIKey

func (f fakeAPIKeys) Validate(_ context.Context, key string) (*apikey.APIKey, error) {
	k, ok := f[key]
	if !ok {
		return nil, apikey.ErrKeyNotFound
	}
	return k, nil
}

// newResourceServer starts a product API protected by the AAuth
// authenticator and, after it, the relying-party authenticator with one
// human API key ("sf_live_human"). /things requires things:read and
// /admin also things:admin.
func newResourceServer(t *testing.T, mode string, trusted ...string) *resourceServer {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := aauthrs.New(aauthrs.Config{
		HTTPClient:     http.DefaultClient,
		Resource:       srv.URL,
		TrustedIssuers: trusted,
		AccessMode:     mode,
		Key:            key,
		Scopes: func(r *http.Request) []string {
			switch r.URL.Path {
			case "/things":
				return []string{"things:read"}
			case "/admin":
				return []string{"things:read", "things:admin"}
			}
			return nil
		},
		ScopeDescriptions:           map[string]string{"things:read": "Read things"},
		InsecureSkipIdentifierCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	auth.Register(mux)

	store := relyingparty.NewMemoryPrincipalStore()
	human, err := store.AddPrincipal(relyingparty.Principal{Email: "human@example.com", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	keys := fakeAPIKeys{"sf_live_human": {ID: uuid.New(), OwnerID: uuid.MustParse(human.ID), Scopes: []string{"things:read"}}}
	rp := relyingparty.NewRequestAuthenticator(relyingparty.BearerConfig{APIKeys: keys, Principals: store})

	rs := &resourceServer{url: srv.URL, auth: auth}
	protected := requestprincipal.Middleware(requestprincipal.Options{}, auth, rp)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := requestprincipal.FromContext(r.Context())
		if !ok {
			t.Error("no principal in context")
		}
		rs.mu.Lock()
		rs.last = p
		rs.mu.Unlock()
		if _, err := io.WriteString(w, "ok "+p.PrincipalID); err != nil {
			t.Error(err)
		}
	}))
	mux.Handle("/things", protected)
	mux.Handle("/admin", protected)
	mux.Handle("/open", protected)
	return rs
}

// --- The AAuth deployment: agent provider and Person Server. ---

type registrar struct{ ps string }

func (r registrar) AuthorizeIssue(context.Context, *http.Request, *agentprovider.IssueRequest) (*agentprovider.Registration, error) {
	return &agentprovider.Registration{Name: "assistant", PS: r.ps}, nil
}

func (registrar) AuthorizeRefresh(context.Context, *agentprovider.RefreshRequest) (*agentprovider.Registration, error) {
	return nil, errors.New("refresh is not used here")
}

func (registrar) AuthorizeSubagent(context.Context, *agentprovider.SubagentRequest) (*agentprovider.SubagentGrant, error) {
	return nil, errors.New("sub-agents are not used here")
}

type deployment struct {
	issuer     string // agent provider and Person Server origin
	agent      *aauth.Agent
	key        crypto.Signer
	agentToken string
	psc        *aauth.PSClient
}

// newDeployment runs an agent provider and a Person Server on one origin
// (the library's own server packages with memory stores) and enrolls an
// agent whose person, alice, approves everything.
func newDeployment(t *testing.T) *deployment {
	t.Helper()
	ctx := t.Context()
	mux := http.NewServeMux()
	origin := httptest.NewServer(mux)
	t.Cleanup(origin.Close)
	issuer := origin.URL

	apKey, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := agentprovider.New(agentprovider.Config{
		HTTPClient: http.DefaultClient,
		Issuer:     issuer, Domain: "agents.example", Key: apKey, Registrar: registrar{ps: issuer},
	})
	if err != nil {
		t.Fatal(err)
	}
	psKey, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := personserver.New(personserver.Config{
		HTTPClient: http.DefaultClient,
		Issuer:     issuer, Key: psKey, SubjectKey: bytes.Repeat([]byte{7}, 32), Store: personserver.NewMemoryStore(),
		Decider: personserver.DeciderFunc(func(_ context.Context, r *personserver.TokenRequest) (personserver.Decision, error) {
			if r.Person == "" {
				return personserver.Allow(personserver.Grant{Person: "alice"}), nil
			}
			return personserver.Allow(personserver.Grant{}), nil
		}),
		MissionApprover: personserver.MissionApproverFunc(func(context.Context, *personserver.MissionRequest) (personserver.Decision, error) {
			return personserver.Allow(personserver.Grant{Mission: &personserver.MissionGrant{ExpiresAt: time.Now().Add(time.Hour)}}), nil
		}),
		InsecureSkipIdentifierCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ap.Register(mux)
	ps.Register(mux)

	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	apc := &agentprovider.Client{BaseURL: issuer}
	issued, err := apc.Issue(ctx, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	ac, err := aauth.VerifyAgentToken(ctx, issued.AgentToken, aauth.VerifyAgentTokenOptions{Resolver: aauth.NewJWKSResolver(http.DefaultClient)})
	if err != nil {
		t.Fatal(err)
	}
	id, err := aauth.ParseAgentIdentifier(ac.Subject)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := aauth.NewAgent(id, aauth.WithKey(key), aauth.WithTokenSource(apc.TokenSource(func(context.Context) (*agentprovider.TokenResponse, error) {
		return issued, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	psc := aauth.NewPSClient(issuer, agent)
	psc.HTTPClient = http.DefaultClient
	if _, err := psc.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	return &deployment{issuer: issuer, agent: agent, key: key, agentToken: issued.AgentToken, psc: psc}
}

func (d *deployment) transport(mission string) *aauth.Transport {
	verify := aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(http.DefaultClient), InsecureSkipIdentifierCheck: true}
	tr := aauth.NewTransport(d.agent, d.psc)
	tr.ResourceVerify, tr.AuthVerify, tr.MissionS256 = verify, verify, mission
	return tr
}

// --- Request helpers. ---

func do(t *testing.T, c *http.Client, req *http.Request) (*http.Response, string) {
	t.Helper()
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(b)
}

func get(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// signedGet signs a GET with key, carrying token in Signature-Key.
func signedGet(t *testing.T, url, token string, key crypto.Signer) *http.Request {
	t.Helper()
	req := get(t, url)
	aauth.AttachSignatureKey(req, token)
	if err := aauth.SignRequest(req, key, ""); err != nil {
		t.Fatal(err)
	}
	return req
}

func requirement(t *testing.T, res *http.Response) aauth.Requirement {
	t.Helper()
	v := res.Header.Get(aauth.HeaderRequirement)
	if v == "" {
		t.Fatalf("status %d: no %s header", res.StatusCode, aauth.HeaderRequirement)
	}
	r, err := aauth.ParseRequirement(v)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// --- Tests. ---

// TestChallengeSequence walks the challenges by hand: no credentials, an
// agent token, then a person token.
func TestChallengeSequence(t *testing.T) {
	d := newDeployment(t)
	rs := newResourceServer(t, aauth.AccessModeAuthToken, d.issuer)
	ctx := t.Context()

	// Unsigned: 401 advertising both AAuth and bearer authentication.
	res, _ := do(t, http.DefaultClient, get(t, rs.url+"/things"))
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned: %d", res.StatusCode)
	}
	if r := requirement(t, res); r.Requirement != aauth.RequirementAgentToken {
		t.Errorf("unsigned: requirement %q", r.Requirement)
	}
	if got := res.Header.Get("WWW-Authenticate"); got != `Bearer realm="api"` {
		t.Errorf("unsigned: WWW-Authenticate %q", got)
	}
	if got, want := res.Header.Get("Link"), aauth.ResourceMetadataLink(rs.url); got != want {
		t.Errorf("unsigned: Link %q, want %q", got, want)
	}

	// Agent token only: the person comes first (draft -11 §6.4).
	res, _ = do(t, http.DefaultClient, signedGet(t, rs.url+"/things", d.agentToken, d.key))
	if res.StatusCode != http.StatusUnauthorized || requirement(t, res).Requirement != aauth.RequirementPersonToken {
		t.Fatalf("agent token: %d %q", res.StatusCode, res.Header.Get(aauth.HeaderRequirement))
	}

	// Person token: requirement=auth-token with a resource token that
	// verifies under the resource's published key.
	personToken, err := d.psc.PersonToken(ctx, aauth.PersonTokenRequest{Resource: rs.url})
	if err != nil {
		t.Fatal(err)
	}
	res, _ = do(t, http.DefaultClient, signedGet(t, rs.url+"/things", personToken, d.key))
	r := requirement(t, res)
	if res.StatusCode != http.StatusUnauthorized || r.Requirement != aauth.RequirementAuthToken || r.ResourceToken == "" {
		t.Fatalf("person token: %d %+v", res.StatusCode, r)
	}
	rc, err := aauth.VerifyResourceChallenge(ctx, r.ResourceToken, aauth.ResourceChallengeOptions{
		TokenVerifyOptions: aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(http.DefaultClient), InsecureSkipIdentifierCheck: true},
		Resource:           rs.url,
		Agent:              d.agent,
		PS:                 d.issuer,
		Presented:          personToken,
	})
	if err != nil {
		t.Fatalf("resource token: %v", err)
	}
	if rc.Scope != "things:read" || rc.Audience[0] != d.issuer {
		t.Errorf("resource token claims: scope %q aud %v", rc.Scope, rc.Audience)
	}
}

// TestFullFlow lets the agent's transport follow every challenge, under a
// mission, and checks the principal the handler sees.
func TestFullFlow(t *testing.T) {
	d := newDeployment(t)
	rs := newResourceServer(t, aauth.AccessModeAuthToken, d.issuer)
	ctx := t.Context()

	// The first access binds the agent to alice; then a mission.
	client := &http.Client{Transport: d.transport(""), Timeout: 30 * time.Second}
	if res, body := do(t, client, get(t, rs.url+"/things")); res.StatusCode != http.StatusOK {
		t.Fatalf("first access: %d %s", res.StatusCode, body)
	}
	m, err := d.psc.ProposeMission(ctx, aauth.MissionProposal{Description: "Tidy the things"})
	if err != nil {
		t.Fatal(err)
	}
	client = &http.Client{Transport: d.transport(m.S256), Timeout: 30 * time.Second}
	res, body := do(t, client, get(t, rs.url+"/things"))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("mission access: %d %s", res.StatusCode, body)
	}
	p := rs.principal()
	switch {
	case p.Type != requestprincipal.TypeAgent, p.Protocol != requestprincipal.ProtocolAAuth:
		t.Errorf("type/protocol: %+v", p)
	case p.Mission != m.S256:
		t.Errorf("mission %q, want %q", p.Mission, m.S256)
	case p.Session == "" || p.Session != p.Proof.TokenID:
		t.Errorf("session %q, token %q", p.Session, p.Proof.TokenID)
	case !p.HasScope("things:read"):
		t.Errorf("scopes %v", p.Scopes)
	case p.Subject == "" || p.PrincipalID != aauthrs.PrincipalID(d.issuer, p.Subject) || p.Delegator != p.PrincipalID:
		t.Errorf("identity: %+v", p)
	case p.Proof.Method != aauth.TypAuth || p.Proof.Issuer != d.issuer || p.Proof.Audience != rs.url:
		t.Errorf("proof: %+v", p.Proof)
	case p.Proof.KeyThumbprint != d.agent.Thumbprint() || p.Actor != "jkt:"+d.agent.Thumbprint():
		t.Errorf("key binding: %+v", p.Proof)
	case p.Proof.Params["signature_input"] == "" || p.Proof.ExpiresAt.Before(time.Now()):
		t.Errorf("proof params: %+v", p.Proof)
	}
	if _, ok := p.Native.(*aauth.AuthClaims); !ok {
		t.Errorf("native: %T", p.Native)
	}

	// A route needing more scope: the transport steps up and gets in.
	if res, body := do(t, client, get(t, rs.url+"/admin")); res.StatusCode != http.StatusOK {
		t.Fatalf("step-up: %d %s", res.StatusCode, body)
	}
	if p := rs.principal(); !p.HasScope("things:admin") {
		t.Errorf("step-up scopes %v", p.Scopes)
	}
}

// TestRejectedAuthTokens presents hand-minted auth tokens.
func TestRejectedAuthTokens(t *testing.T) {
	trusted := newFakeIssuer(t)
	foreign := newFakeIssuer(t)
	rs := newResourceServer(t, aauth.AccessModeAuthToken, trusted.url)

	agentKey, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	agentJWK, err := aauth.NewJWK(agentKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	valid := trusted.authToken(t, rs.url, agentJWK, now, now.Add(10*time.Minute))

	res, body := do(t, http.DefaultClient, signedGet(t, rs.url+"/things", valid, agentKey))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("valid token: %d %s", res.StatusCode, body)
	}
	p := rs.principal()
	if p.Organization != "org-1" || p.Mission != "mission-digest" || p.Subject != "directed-person" ||
		p.PrincipalID != trusted.url+"#directed-person" {
		t.Errorf("principal: %+v", p)
	}

	cases := []struct {
		name, token string
		key         crypto.Signer
		sigError    string
	}{
		{"wrong audience", trusted.authToken(t, "https://other.example", agentJWK, now, now.Add(10*time.Minute)), agentKey, aauth.SigErrInvalidJWT},
		{"expired", trusted.authToken(t, rs.url, agentJWK, now.Add(-20*time.Minute), now.Add(-10*time.Minute)), agentKey, aauth.SigErrExpiredJWT},
		{"foreign key", valid, otherKey, aauth.SigErrInvalidSignature},
		{"untrusted issuer", foreign.authToken(t, rs.url, agentJWK, now, now.Add(10*time.Minute)), agentKey, aauth.SigErrInvalidJWT},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := do(t, http.DefaultClient, signedGet(t, rs.url+"/things", tc.token, tc.key))
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status %d", res.StatusCode)
			}
			se, err := aauth.SignatureErrorFromResponse(res)
			if err != nil {
				t.Fatal(err)
			}
			if se.Code != tc.sigError {
				t.Errorf("Signature-Error %q, want %q", se.Code, tc.sigError)
			}
		})
	}
	if n := foreign.fetches.Load(); n != 0 {
		t.Errorf("the untrusted issuer was contacted %d times", n)
	}

	// Insufficient scope: a step-up challenge against the auth token.
	res, _ = do(t, http.DefaultClient, signedGet(t, rs.url+"/admin", valid, agentKey))
	if r := requirement(t, res); res.StatusCode != http.StatusUnauthorized || r.Requirement != aauth.RequirementAuthToken || r.ResourceToken == "" {
		t.Errorf("step-up: %d %+v", res.StatusCode, r)
	}

	// A malformed Signature-Key is a signature failure, not "no credentials".
	req := get(t, rs.url+"/things")
	req.Header.Set("Signature-Key", "garbage")
	if res, _ := do(t, http.DefaultClient, req); res.StatusCode != http.StatusUnauthorized || res.Header.Get(aauth.HeaderSignatureError) == "" {
		t.Errorf("malformed Signature-Key: %d %v", res.StatusCode, res.Header)
	}
}

// TestHumanRequestInChain checks that the relying-party authenticator after
// the AAuth one still serves human credentials.
func TestHumanRequestInChain(t *testing.T) {
	rs := newResourceServer(t, aauth.AccessModeAuthToken, newFakeIssuer(t).url)
	req := get(t, rs.url+"/things")
	req.Header.Set("X-API-Key", "sf_live_human")
	res, body := do(t, http.DefaultClient, req)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("API key: %d %s", res.StatusCode, body)
	}
	p := rs.principal()
	if p.Type != requestprincipal.TypeHuman || p.Protocol != requestprincipal.ProtocolAPIKey || !p.HasScope("things:read") {
		t.Errorf("human principal: %+v", p)
	}
	if _, ok := p.Native.(*relyingparty.AuthenticatedPrincipal); !ok {
		t.Errorf("native: %T", p.Native)
	}

	// An invalid key gets the bearer challenge, not an AAuth one.
	req = get(t, rs.url+"/things")
	req.Header.Set("Authorization", "Bearer sf_live_unknown")
	res, _ = do(t, http.DefaultClient, req)
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get("WWW-Authenticate"), `error="invalid_token"`) ||
		res.Header.Get(aauth.HeaderRequirement) != "" {
		t.Errorf("invalid key: %d %v", res.StatusCode, res.Header)
	}
}

// TestAgentTokenMode serves a bare agent token on a route needing no
// scope, and still requires a person for scoped routes.
func TestAgentTokenMode(t *testing.T) {
	d := newDeployment(t)
	rs := newResourceServer(t, aauth.AccessModeAgentToken, d.issuer)

	res, body := do(t, http.DefaultClient, signedGet(t, rs.url+"/open", d.agentToken, d.key))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("agent token: %d %s", res.StatusCode, body)
	}
	p := rs.principal()
	if p.Type != requestprincipal.TypeAgent || p.Subject != d.agent.ID.String() || p.PrincipalID != p.Subject ||
		p.Proof.Method != aauth.TypAgent || p.Proof.Issuer != d.issuer || p.Proof.KeyThumbprint != d.agent.Thumbprint() {
		t.Errorf("agent principal: %+v", p)
	}
	res, _ = do(t, http.DefaultClient, signedGet(t, rs.url+"/things", d.agentToken, d.key))
	if res.StatusCode != http.StatusUnauthorized || requirement(t, res).Requirement != aauth.RequirementPersonToken {
		t.Errorf("scoped route: %d", res.StatusCode)
	}
}

func TestMetadata(t *testing.T) {
	rs := newResourceServer(t, aauth.AccessModeAuthToken, newFakeIssuer(t).url)
	var md aauth.ResourceMetadata
	if err := aauth.FetchMetadata(t.Context(), http.DefaultClient, rs.url, aauth.WellKnownResource, &md); err != nil {
		t.Fatal(err)
	}
	if md.Issuer != rs.url || md.JWKSURI != rs.url+aauthrs.DefaultJWKSPath || md.AccessMode != aauth.AccessModeAuthToken ||
		md.ScopeDescriptions["things:read"] == "" {
		t.Errorf("metadata: %+v", md)
	}
	if err := md.Validate(); err != nil {
		t.Error(err)
	}
	res, body := do(t, http.DefaultClient, get(t, md.JWKSURI))
	var set aauth.JWKS
	if err := json.Unmarshal([]byte(body), &set); err != nil || res.StatusCode != http.StatusOK || len(set.Keys) != 1 {
		t.Errorf("jwks: %d %s %v", res.StatusCode, body, err)
	}
}

func TestNewValidation(t *testing.T) {
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]aauthrs.Config{
		"no resource":        {TrustedIssuers: []string{"https://ps.example"}, Key: key},
		"http resource":      {Resource: "http://api.example", TrustedIssuers: []string{"https://ps.example"}, Key: key},
		"no issuers":         {Resource: "https://api.example", Key: key},
		"bad issuer":         {Resource: "https://api.example", TrustedIssuers: []string{"https://ps.example/path"}, Key: key},
		"no key":             {Resource: "https://api.example", TrustedIssuers: []string{"https://ps.example"}},
		"session-token mode": {Resource: "https://api.example", TrustedIssuers: []string{"https://ps.example"}, Key: key, AccessMode: aauth.AccessModeSessionToken},
	} {
		if _, err := aauthrs.New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := aauthrs.New(aauthrs.Config{Resource: "https://api.example", AccessMode: aauth.AccessModeAgentToken}); err != nil {
		t.Errorf("agent-token mode without key or issuers: %v", err)
	}
}
