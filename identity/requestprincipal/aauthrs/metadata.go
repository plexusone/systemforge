package aauthrs

import (
	"encoding/json"
	"net/http"
	"strings"

	aauth "github.com/aauth-dev/auth-go"
)

// Metadata returns the resource's aauth-resource.json document (draft
// §11.2.4): issuer, jwks_uri (when it issues resource tokens), the access
// mode, scope descriptions, and the signature requirements.
func (a *Authenticator) Metadata() aauth.ResourceMetadata {
	sm := a.cfg.Metadata
	sm.Issuer = a.cfg.Resource
	if a.cfg.Key != nil {
		sm.JWKSURI = strings.TrimSuffix(a.cfg.Resource, "/") + a.cfg.JWKSPath
	}
	if len(sm.AcceptSignatureAlgs) == 0 {
		sm.AcceptSignatureAlgs = aauth.AcceptedSignatureAlgs()
	}
	return aauth.ResourceMetadata{
		ServerMetadata:                sm,
		AccessMode:                    a.cfg.AccessMode,
		ScopeDescriptions:             a.cfg.ScopeDescriptions,
		SignatureWindow:               int(a.cfg.Signature.Window.Seconds()),
		AdditionalSignatureComponents: a.cfg.Signature.RequiredComponents,
	}
}

// JWKS returns the key set holding the resource token signing key (empty
// when the resource issues none).
func (a *Authenticator) JWKS() aauth.JWKS {
	if a.cfg.Key == nil {
		return aauth.JWKS{Keys: []aauth.JWK{}}
	}
	return aauth.JWKS{Keys: []aauth.JWK{a.jwk}}
}

// MetadataHandler serves Metadata as JSON.
func (a *Authenticator) MetadataHandler() http.Handler {
	return jsonHandler(func() any { return a.Metadata() })
}

// JWKSHandler serves JWKS as JSON.
func (a *Authenticator) JWKSHandler() http.Handler {
	return jsonHandler(func() any { return a.JWKS() })
}

// Register mounts the metadata document at
// /.well-known/aauth-resource.json and the JWKS at Config.JWKSPath. Agents
// and Person Servers discover the resource's key there to verify resource
// tokens. Mount them outside the authentication middleware.
func (a *Authenticator) Register(mux *http.ServeMux) {
	mux.Handle("GET /.well-known/"+aauth.WellKnownResource, a.MetadataHandler())
	mux.Handle("GET "+a.cfg.JWKSPath, a.JWKSHandler())
}

func jsonHandler(body func() any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		// Headers are sent with the first write; an encoding failure here
		// can only be a broken connection, which the client observes.
		if err := json.NewEncoder(w).Encode(body()); err != nil {
			return
		}
	})
}
