// Package displayname keeps an email address from being shown as a person's
// name.
//
// A name is shown to other people (profiles, member lists, certificates), and
// an address is not the person's to publish. SystemAuth asks for a name instead
// of making one from the address (ADR-024); this package is the one place a
// host, a relying-party store or a client library turns "a name, or nothing"
// into something safe to show, so no application writes its own.
package displayname

import "strings"

// Default names a person who gave no usable name. It says nothing about them.
const Default = "Member"

// LooksLikeAddress reports whether s is, or contains, an email address: it has
// an "@". Names are refused with an "@" at sign-up, so a stored name with one
// is an address or an accident, not a name to show.
func LooksLikeAddress(s string) bool {
	return strings.Contains(s, "@")
}

// Safe returns name trimmed, or "" when it is empty or looks like an address.
// Use it where "no name" is a meaningful answer, such as deciding whether to
// ask for one.
func Safe(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || LooksLikeAddress(name) {
		return ""
	}
	return name
}

// Or returns Safe(name), or fallback when there is none. The fallback is used
// as given: pass a neutral word, never an address.
func Or(name, fallback string) string {
	if n := Safe(name); n != "" {
		return n
	}
	return fallback
}

// Show returns the name to display for a person: Safe(name), else Default.
func Show(name string) string {
	return Or(name, Default)
}
