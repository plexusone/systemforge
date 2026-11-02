package systemauth

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"net/http"
)

// PageStylePath serves the stylesheet SystemAuth's own pages link: sign-in,
// sign-out, consent, sign-up and the email pages. It is served from the
// issuer's origin, which the pages' content security policy allows.
const PageStylePath = "/assets/systemauth.css"

//go:embed assets/page.css
var pageStyle []byte

// pageStyleVersion names this build's stylesheet in its link, so a browser
// fetches it again when it changes and may cache it otherwise.
var pageStyleVersion = func() string {
	sum := sha256.Sum256(pageStyle)
	return hex.EncodeToString(sum[:6])
}()

// pageStyleLink is the <link> every page's head carries, after its
// viewport.
var pageStyleLink = `<link rel="stylesheet" href="` + PageStylePath + `?v=` + pageStyleVersion + `">`

// handlePageStyle serves GET PageStylePath.
func handlePageStyle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	// The link names the content, so a versioned request may be cached
	// for long; an unversioned one is checked again within the hour.
	if r.URL.Query().Get("v") == pageStyleVersion {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
	if _, err := w.Write(pageStyle); err != nil {
		LoggerFromContext(r.Context()).Debug("writing the page stylesheet", "error", err)
	}
}
