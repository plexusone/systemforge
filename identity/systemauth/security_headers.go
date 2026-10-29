package systemauth

import (
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Security headers on every SystemAuth response. The HTML pages (login,
// consent, sign-up, sign-up code, waitlist, age question, logout) load
// nothing and run no script or inline style, so their content security
// policy allows only the page's own origin and no inline code. The headers
// are harmless on JSON responses and redirects: they do not affect CORS,
// and on a redirect the referrer policy keeps the URL that carried a code
// or token out of the next request.
const (
	// cspBase is the content security policy without form-action.
	cspBase = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'"

	// hstsValue is sent when the issuer is https.
	hstsValue = "max-age=31536000; includeSubDomains"

	// referrerPolicy sends a referrer only to the issuer's own origin: no
	// page's URL, such as one with an invite code, leaks to a provider or
	// an application, while a same-origin form post keeps its Origin
	// header, which the form handlers check (with no-referrer browsers send
	// "Origin: null").
	referrerPolicy = "same-origin"
)

// contentSecurityPolicy returns the page policy whose form-action allows
// the page's own origin and the given sources.
func contentSecurityPolicy(formTargets ...string) string {
	return cspBase + "; form-action " + strings.Join(append([]string{"'self'"}, formTargets...), " ")
}

// securityHeaders sets the security headers on every response. A page
// whose form submission redirects to another origin widens form-action
// with allowFormTargets: browsers check form-action on each redirect that
// follows a submission.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	hsts := strings.HasPrefix(strings.ToLower(s.config.Issuer), "https://")
	csp := contentSecurityPolicy()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", referrerPolicy)
		if hsts {
			h.Set("Strict-Transport-Security", hstsValue)
		}
		next.ServeHTTP(w, r)
	})
}

// allowFormTargets widens the page's form-action to the given sources
// (see formSources).
func allowFormTargets(w http.ResponseWriter, sources []string) {
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy(sources...))
}

// allowImageSource lets the page load images from its own origin and from
// origin, an https origin whose host matches cspHost (the login page shows
// the requesting client's logo).
func allowImageSource(w http.ResponseWriter, origin string) {
	w.Header().Set("Content-Security-Policy", cspBase+"; img-src 'self' "+origin+"; form-action 'self'")
}

// cspScheme matches a URI scheme usable as a CSP scheme source.
var cspScheme = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)

// cspHost matches a host (name, IPv4 or bracketed IPv6) and optional port
// usable in a CSP host source.
var cspHost = regexp.MustCompile(`^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(:[0-9]+)?$`)

// formSources returns the CSP sources a form submission may redirect to
// for the given URLs: the origin of an http(s) URL (any port for a
// loopback host, which a native application's redirect URI may change), or
// the scheme of a private-use URI. Values that cannot be expressed safely
// are left out.
func formSources(urls ...string) []string {
	var out []string
	add := func(src string) {
		if !slices.Contains(out, src) {
			out = append(out, src)
		}
	}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" {
			continue
		}
		scheme := strings.ToLower(u.Scheme)
		if !cspScheme.MatchString(scheme) {
			continue
		}
		if scheme != "http" && scheme != "https" {
			add(scheme + ":")
			continue
		}
		host := strings.ToLower(u.Host)
		if host == "" || !cspHost.MatchString(host) {
			continue
		}
		if loopbackHost(u.Hostname()) {
			add(scheme + "://" + bracketHost(u.Hostname()) + ":*")
			continue
		}
		add(scheme + "://" + host)
	}
	return out
}

// loopbackHost reports whether host is localhost or a loopback address.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// bracketHost brackets an IPv6 address for use in an origin.
func bracketHost(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}
