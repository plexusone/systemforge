package systemauth

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/oauthclient"
)

const (
	// SignInMethodsPath shows a signed-in person their account's sign-in
	// methods and lets them link another provider's sign-in to the same
	// account, so either signs them in.
	SignInMethodsPath = "/account/sign-in-methods"
	// linkStartPattern starts linking a provider: a POST from the page.
	linkStartPattern = SignInMethodsPath + "/{provider}"

	// EventSignInMethodLinked records linking a provider's sign-in to an
	// account, or a refusal to (Details: method, and reason on failure).
	EventSignInMethodLinked = "systemauth.sign_in_method.linked"

	// linkNoncePrefix marks a login state that links to the account named
	// after it rather than signing in.
	linkNoncePrefix = "link:"
)

var signInMethodsTemplate = template.Must(template.New("sign-in-methods").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` + pageStyleLink + `
<title>Sign-in methods</title></head>
<body><main><h1>Sign-in methods</h1>
{{with .Email}}<p>Signed in as <strong>{{.}}</strong>.</p>
{{end}}{{with .JustLinked}}<p role="status">{{.}} is linked to your account. You can now sign in with it.</p>
{{end}}{{with .Problem}}<p role="alert">{{.}}</p>
{{end}}{{if .Linked}}<h2>Linked</h2>
<ul>{{range .Linked}}<li>{{.}}</li>{{end}}</ul>
{{end}}{{if .Providers}}<p>Link another sign-in to this account, so either one signs you in to the same account and its work.</p>
<nav aria-label="Link a sign-in method">
{{range .Providers}}<form method="post" action="{{.Action}}">{{with $.ReturnTo}}<input type="hidden" name="return_to" value="{{.}}">{{end}}<button type="submit">Link {{.Name}}</button></form>
{{end}}</nav>
{{else}}<p>Every available sign-in method is linked to this account.</p>
{{end}}{{with .Back}}<p><a href="{{.URL}}">Back to {{.Name}}</a></p>
{{end}}</main></body></html>
`))

// linkProblems are the page's messages for a refused link, by reason.
var linkProblems = map[string]string{
	"other_account": "That sign-in already belongs to another account, so it was not linked. Signing in with it opens that other account; removing a sign-in method or merging accounts is not available yet.",
	"session":       "You were signed out while linking. Sign in and try again.",
	"failed":        "Linking did not complete. Try again.",
}

// returnTo is the validated return_to: where the page's back link goes, an
// allowed redirect target, or "" for none. An invalid one is dropped, never
// followed.
func (sl *socialLogin) returnTo(raw string) string {
	if raw == "" {
		return ""
	}
	v, err := sl.redirects.validate(raw)
	if err != nil {
		return ""
	}
	return v
}

// methodsURL is the sign-in methods page's address, keeping returnTo (already
// validated) and adding extra, such as the outcome of a link.
func methodsURL(returnTo string, extra url.Values) string {
	q := url.Values{}
	for k, v := range extra {
		q[k] = v
	}
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	if len(q) == 0 {
		return SignInMethodsPath
	}
	return SignInMethodsPath + "?" + q.Encode()
}

// signInFirst sends a browser without a login session to sign in, and back
// to the page with its return_to.
func signInFirst(w http.ResponseWriter, r *http.Request, returnTo string, status int) {
	http.Redirect(w, r, LoginPath+"?return_to="+url.QueryEscape(methodsURL(returnTo, nil)), status)
}

// handleSignInMethods serves GET SignInMethodsPath: the account's email,
// the sign-in methods linked to it, a Link button for each one that is not,
// and, with a valid return_to, a link back to the app. Without a login
// session it sends the browser to sign in first, and back here.
func (sl *socialLogin) handleSignInMethods(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	noStore(w)
	q := r.URL.Query()
	returnTo := sl.returnTo(q.Get("return_to"))
	sess, err := sl.currentSession(r)
	if err != nil {
		signInFirst(w, r, returnTo, http.StatusFound)
		return
	}
	var email string
	if p, err := sl.directory.GetPrincipal(ctx, sess.PrincipalID); err == nil {
		email = p.Email
	}
	var linked []string
	if lister, ok := sl.directory.(LinkedProviderLister); ok {
		linked, err = lister.LinkedProviders(ctx, sess.PrincipalID)
		if err != nil {
			LoggerFromContext(ctx).Error("listing linked sign-in methods", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	type provider struct{ Name, Action string }
	var providers []provider
	var linkedNames, authorizeURLs []string
	for _, p := range sl.providers {
		if slices.Contains(linked, p) {
			linkedNames = append(linkedNames, displayName(p))
			continue
		}
		providers = append(providers, provider{Name: displayName(p), Action: SignInMethodsPath + "/" + url.PathEscape(p)})
		// Each form's POST is answered with a redirect to the provider,
		// which form-action must allow.
		authorizeURLs = append(authorizeURLs, sl.connectors[p].AuthCodeURL("state"))
	}
	var justLinked string
	if p := q.Get("linked"); p != "" && sl.connectors[p] != nil {
		justLinked = displayName(p)
	}
	type back struct{ URL, Name string }
	var backLink *back
	if returnTo != "" {
		name := sl.redirects.signedOutName
		if name == "" {
			name = hostOf(returnTo, sl.redirects.issuerOrigin)
		}
		backLink = &back{URL: returnTo, Name: name}
	}
	if len(authorizeURLs) > 0 {
		allowFormTargets(w, formSources(authorizeURLs...))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := signInMethodsTemplate.Execute(w, struct {
		Email, JustLinked, Problem, ReturnTo string
		Linked                               []string
		Providers                            []provider
		Back                                 *back
	}{email, justLinked, linkProblems[q.Get("error")], returnTo, linkedNames, providers, backLink}); err != nil {
		LoggerFromContext(ctx).Error("rendering sign-in methods page", "error", err)
	}
}

// handleLinkStart serves POST linkStartPattern: it starts the provider's
// sign-in with a login state that links the result to the signed-in
// account instead of signing in.
//
// CSRF: the request must come from the issuer's origin or an allowed
// relying-party origin, as sign-out's does, and the browser must hold a
// login session; the callback checks the session again.
func (sl *socialLogin) handleLinkStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	noStore(w)
	if !sl.redirects.fromTrustedOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if !sl.limit(w, r, "social_login_start", DefaultSocialLoginLimit) {
		return
	}
	provider := chi.URLParam(r, "provider")
	conn, ok := sl.connectors[provider]
	if !ok {
		http.NotFound(w, r)
		return
	}
	returnTo := sl.returnTo(r.PostFormValue("return_to"))
	sess, err := sl.currentSession(r)
	if err != nil {
		signInFirst(w, r, returnTo, http.StatusSeeOther)
		return
	}
	state, err := oauthclient.GenerateState()
	if err != nil {
		logger.Error("generating link state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	if err := sl.states.Put(ctx, state, oauthclient.StateData{
		Provider:     provider,
		RedirectURL:  methodsURL(returnTo, nil),
		Nonce:        linkNoncePrefix + sess.PrincipalID.String(),
		PKCEVerifier: verifier,
	}, loginStateTTL); err != nil {
		logger.Error("storing link state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sl.cookies.setState(w, state, loginStateTTL)
	//nolint:gosec // G710: redirect target is the configured provider's authorization endpoint
	http.Redirect(w, r, conn.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusSeeOther)
}

// linkingPrincipal returns the account a login state links to, when it is
// a link and not a sign-in.
func linkingPrincipal(nonce string) (uuid.UUID, bool) {
	rest, ok := strings.CutPrefix(nonce, linkNoncePrefix)
	if !ok {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(rest)
	return id, err == nil
}

// completeLink links login's identity to principalID, the account that
// started the link, and returns the browser to the sign-in methods page,
// with the return_to the link started with (page, from the login state),
// validated again.
// The browser must still be signed in as that account. An identity already
// on another account is never moved; one already on this account is a
// success. No account is created, and the account's email is unchanged.
func (sl *socialLogin) completeLink(ctx context.Context, w http.ResponseWriter, r *http.Request, page string, principalID uuid.UUID, login ExternalLogin) {
	var returnTo string
	if u, err := url.Parse(page); err == nil {
		returnTo = sl.returnTo(u.Query().Get("return_to"))
	}
	back := func(param, value string) {
		http.Redirect(w, r, methodsURL(returnTo, url.Values{param: {value}}), http.StatusFound)
	}
	sess, err := sl.currentSession(r)
	if err != nil || sess.PrincipalID != principalID {
		sl.linkRefused(ctx, principalID, login.Provider, "session")
		back("error", "session")
		return
	}
	existing, err := sl.directory.FindByExternalIdentity(ctx, login.Provider, login.Subject)
	switch {
	case err == nil && existing.ID == principalID:
		back("linked", login.Provider)
		return
	case err == nil:
		sl.linkRefused(ctx, principalID, login.Provider, "other_account")
		back("error", "other_account")
		return
	case !errors.Is(err, ErrPrincipalNotFound):
		LoggerFromContext(ctx).Error("looking up the identity to link", "error", err)
		back("error", "failed")
		return
	}
	if err := sl.directory.LinkExternalIdentity(ctx, principalID, login); err != nil {
		if errors.Is(err, ErrExternalIdentityExists) {
			sl.linkRefused(ctx, principalID, login.Provider, "other_account")
			back("error", "other_account")
			return
		}
		LoggerFromContext(ctx).Error("linking an identity", "error", err)
		back("error", "failed")
		return
	}
	sl.emit(ctx, &audit.Event{
		EventType: EventSignInMethodLinked,
		Action:    "link_sign_in_method",
		Actor:     audit.Actor{ID: principalID, Type: actorPrincipal},
		Resource:  audit.Resource{Type: "principal", ID: principalID},
		Details:   details("method", login.Provider),
	})
	LoggerFromContext(ctx).Info("sign-in method linked", "principal_id", principalID, "provider", login.Provider)
	back("linked", login.Provider)
}

// linkRefused records a refused link.
func (sl *socialLogin) linkRefused(ctx context.Context, principalID uuid.UUID, provider, reason string) {
	sl.emit(ctx, &audit.Event{
		EventType: EventSignInMethodLinked,
		Action:    "link_sign_in_method",
		Actor:     audit.Actor{ID: principalID, Type: actorPrincipal},
		Resource:  audit.Resource{Type: "principal", ID: principalID},
		Outcome:   audit.OutcomeFailure,
		Details:   details("method", provider, "reason", reason),
	})
}

// displayName is a provider's name for people.
func displayName(provider string) string {
	if name := providerDisplayNames[provider]; name != "" {
		return name
	}
	return provider
}
