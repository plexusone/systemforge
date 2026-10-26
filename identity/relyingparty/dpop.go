package relyingparty

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/grokify/goauth/dpop"
)

// DPoPReplayCache records DPoP proof identifiers so that each proof is
// accepted once. Implementations must be safe for concurrent use and, when
// several instances serve the API, shared between them. The replay caches
// in session/middleware (NewMemoryReplayCache, NewRedisReplayCache)
// implement it.
type DPoPReplayCache interface {
	// Use records key until expiresAt and reports whether it was already
	// recorded (a replay).
	Use(ctx context.Context, key string, expiresAt time.Time) (replayed bool, err error)
}

// DPoPConfig enables DPoP sender-constrained access tokens (RFC 9449) in
// BearerMiddleware.
type DPoPConfig struct {
	// Verification sets the proof age window and clock skew. Access token
	// binding (the ath claim) is always required. Zero values use
	// dpop.DefaultVerificationConfig.
	Verification dpop.VerificationConfig

	// ReplayCache rejects a proof whose jti has been used before
	// (required).
	ReplayCache DPoPReplayCache

	// BaseURL is the scheme and host clients use to reach this API, such as
	// "https://api.example.com"; a proof's htu must equal BaseURL plus the
	// request path. If empty, the scheme comes from the connection and the
	// host from the Host header. Forwarded headers are never trusted, so
	// set BaseURL behind a proxy that terminates TLS.
	BaseURL string
}

// dpopVerifier checks DPoP proofs for BearerMiddleware.
type dpopVerifier struct {
	verifier *dpop.Verifier
	maxAge   time.Duration
	cache    DPoPReplayCache
	baseURL  string
}

func newDPoPVerifier(cfg *DPoPConfig) *dpopVerifier {
	if cfg.ReplayCache == nil {
		panic("relyingparty: DPoPConfig.ReplayCache is required")
	}
	vc := cfg.Verification
	def := dpop.DefaultVerificationConfig()
	if vc.MaxAge <= 0 {
		vc.MaxAge = def.MaxAge
	}
	if vc.AllowedClockSkew <= 0 {
		vc.AllowedClockSkew = def.AllowedClockSkew
	}
	vc.RequireAccessTokenBinding = true
	return &dpopVerifier{
		verifier: dpop.NewVerifier(vc),
		maxAge:   vc.MaxAge + 2*vc.AllowedClockSkew,
		cache:    cfg.ReplayCache,
		baseURL:  strings.TrimSuffix(cfg.BaseURL, "/"),
	}
}

// verify checks that r carries exactly one fresh, unreplayed DPoP proof for
// its method and URI, bound to token and signed by the key whose
// thumbprint is jkt. Proof failures are bearerErrors; a replay cache
// failure is returned as is.
func (v *dpopVerifier) verify(r *http.Request, token, jkt string) error {
	proofs := r.Header.Values(dpop.HeaderDPoP)
	if len(proofs) != 1 || proofs[0] == "" {
		return errUnauthenticated("invalid_dpop_proof", "a single DPoP proof is required")
	}
	result, err := v.verifier.Verify(r.Context(), dpop.VerificationRequest{
		Proof:       proofs[0],
		Method:      r.Method,
		URI:         v.requestURI(r),
		AccessToken: token,
	})
	if err != nil {
		return errUnauthenticated("invalid_dpop_proof", "invalid DPoP proof")
	}
	if err := dpop.VerifyTokenBinding(jkt, result.Thumbprint); err != nil {
		return errUnauthenticated("invalid_token", "DPoP proof key does not match the token")
	}
	replayed, err := v.cache.Use(r.Context(), result.Thumbprint+":"+result.JTI, result.IssuedAt.Add(v.maxAge))
	if err != nil {
		return err
	}
	if replayed {
		return errUnauthenticated("invalid_dpop_proof", "DPoP proof replayed")
	}
	return nil
}

// requestURI is the htu a proof for r must carry.
func (v *dpopVerifier) requestURI(r *http.Request) string {
	if v.baseURL != "" {
		return v.baseURL + r.URL.Path
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}
