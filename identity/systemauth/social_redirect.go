package systemauth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// redirectPolicy validates post-login return_to targets. A target is allowed
// when it is a same-origin relative path, or an absolute URL whose origin is
// the issuer's origin or one of the configured allowed origins. Nothing that
// would let an attacker bounce a freshly signed-in user to an arbitrary site
// (open redirect) passes.
type redirectPolicy struct {
	defaultTarget string
	issuerOrigin  string
	origins       map[string]bool
}

func newRedirectPolicy(issuer string, cfg *SocialLoginConfig) (*redirectPolicy, error) {
	p := &redirectPolicy{defaultTarget: cfg.DefaultRedirect, origins: map[string]bool{}}
	issuerOrigin, err := parseOrigin(issuer)
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	p.issuerOrigin = issuerOrigin
	p.origins[issuerOrigin] = true
	for _, o := range cfg.AllowedRedirectOrigins {
		origin, err := parseOrigin(o)
		if err != nil {
			return nil, err
		}
		p.origins[origin] = true
	}
	if _, err := p.validate(p.defaultTarget); err != nil {
		return nil, fmt.Errorf("default_redirect: %w", err)
	}
	return p, nil
}

// resolve returns the validated target, or the default when raw is empty.
func (p *redirectPolicy) resolve(raw string) (string, error) {
	if raw == "" {
		return p.defaultTarget, nil
	}
	return p.validate(raw)
}

func (p *redirectPolicy) validate(raw string) (string, error) {
	if raw == "" || len(raw) > 2048 {
		return "", ErrRedirectNotAllowed
	}
	// Browsers treat backslashes as slashes and strip tabs/newlines, which
	// turns "/\evil.com" or "/\t/evil.com" into a protocol-relative URL.
	if strings.ContainsAny(raw, "\\\t\r\n") {
		return "", ErrRedirectNotAllowed
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "", ErrRedirectNotAllowed
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", ErrRedirectNotAllowed
	}
	if u.User != nil {
		return "", ErrRedirectNotAllowed
	}

	if u.Scheme == "" && u.Host == "" {
		// Relative: must be an absolute path on this origin, never "//host".
		if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
			return "", ErrRedirectNotAllowed
		}
		return u.String(), nil
	}

	origin, err := parseOrigin(raw)
	if err != nil || !p.origins[origin] {
		return "", ErrRedirectNotAllowed
	}
	return u.String(), nil
}

// parseOrigin normalizes an absolute http(s) URL to scheme://host[:port].
func parseOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid origin %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "https" && scheme != "http") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("invalid origin %q: must be an absolute http(s) URL", raw)
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}

// requestOrigin returns the normalized origin a browser attached to r (the
// Origin header, else the Referer), or "" when there is none.
func requestOrigin(r *http.Request) string {
	for _, h := range []string{r.Header.Get("Origin"), r.Header.Get("Referer")} {
		if h == "" || h == "null" {
			continue
		}
		origin, err := parseOrigin(h)
		if err != nil {
			return ""
		}
		return origin
	}
	return ""
}

// fromIssuer reports whether r was sent by a page on the issuer's origin.
func (p *redirectPolicy) fromIssuer(r *http.Request) bool {
	return requestOrigin(r) == p.issuerOrigin
}

// fromTrustedOrigin reports whether r was sent by a page on the issuer's
// origin or an allowed relying-party origin.
func (p *redirectPolicy) fromTrustedOrigin(r *http.Request) bool {
	origin := requestOrigin(r)
	return origin != "" && p.origins[origin]
}
