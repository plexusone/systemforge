package ocsfaudit

import (
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// kind is the shape an allowed detail must have. A value of another shape
// is left out, so a caller that puts an email address or free text where a
// code belongs does not get it into the OCSF event.
type kind int

const (
	kindCode     kind = iota // a short code: letters, digits and _ . : / + = -
	kindCodeList             // a list of codes
	kindUUID                 // a UUID
	kindUUIDList             // a list of UUIDs
	kindBool                 // a boolean
	kindInt                  // an integer
	kindTime                 // a time, written as RFC 3339 in UTC
	kindManagers             // managed-principal managers: principal_id and role
)

// codePattern is what a code detail may hold. It has no space and no @, so
// neither prose nor an email address passes.
var codePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/+=-]{0,127}$`)

// allowed lists, per event type, the Details keys that may reach an OCSF
// event and their shape. Keys not listed are never copied: no detail of an
// event type missing here is.
var allowed = map[string]map[string]kind{
	"systemauth.sign_in":                  {"method": kindCode, "client_id": kindCode, "reason": kindCode},
	"systemauth.sign_out":                 {"method": kindCode, "tokens_revoked": kindBool},
	"systemauth.token.refused":            {"grant_type": kindCode, "client_id": kindCode, "reason": kindCode, "error": kindCode},
	"systemauth.refresh_token.reuse":      {"grant_type": kindCode, "client_id": kindCode, "family_revoked": kindBool},
	"systemauth.authorization_code.reuse": {"grant_type": kindCode, "client_id": kindCode, "family_revoked": kindBool},
	"systemauth.token.revoked":            {"client_id": kindCode, "token_type_hint": kindCode, "error": kindCode},
	"systemauth.token_family.revoked":     {"reason": kindCode, "subject": kindUUID, "client_id": kindCode},
	"systemauth.email_verification.sent":  {"purpose": kindCode, "sent": kindBool},
	"systemauth.email.verified":           {"purpose": kindCode, "method": kindCode},
	"systemauth.signing_key.loaded":       {"key_id": kindCode, "verification_key_ids": kindCodeList, "ephemeral": kindBool},
	"systemauth.production.waiver":        {"check": kindCode, "setting": kindCode},

	"organization.membership": {
		"organization_id": kindUUID, "principal_id": kindUUID, "role": kindCode, "old_role": kindCode,
		"was_active": kindBool, "active": kindBool, "previous_owner_id": kindUUID, "previous_owner_role": kindCode,
	},
	"service_account": {
		"organization_id": kindUUID, "key_id": kindCode, "algorithm": kindCode, "expires_at": kindTime,
		"reason": kindCode, "application": kindCode, "role": kindCode,
	},
	"keys":        {"purpose": kindCode, "outcome": kindCode, "event_id": kindCode, "reason": kindCode, "dek_id": kindCode},
	"connections": {"provider": kindCode, "reason": kindCode},

	"scim_token.issued":                {"generation": kindInt, "revoked": kindUUIDList},
	"scim_token.rotated":               {"generation": kindInt, "revoked": kindUUIDList},
	"scim_token.revoked":               {"generation": kindInt},
	"scim_token.authentication_failed": {"reason": kindCode},

	"signup_code.created":     {"kind": kindCode, "max_uses": kindInt},
	"signup_code.redeemed":    {"provider": kindCode},
	"signup_allowance.set":    {"granted": kindInt},
	"signup_code.revoked":     {},
	"signup_invite.created":   {},
	"signup_invite.revoked":   {},
	"signup_waitlist.invited": {},

	"managed_principal.created":                 {"client_id": kindCode, "managers": kindManagers, "has_email": kindBool},
	"managed_principal.deleted":                 countKeys,
	"managed_principal.all_revoked":             countKeys,
	"managed_principal.released":                {"managers": kindManagers},
	"managed_principal.manager_added":           {"manager_principal_id": kindUUID, "role": kindCode},
	"managed_principal.manager_removed":         {"manager_principal_id": kindUUID, "role": kindCode},
	"managed_principal.claim_redeemed":          {"manager_principal_id": kindUUID, "role": kindCode},
	"managed_principal.manager_invite_accepted": {"manager_principal_id": kindUUID, "role": kindCode},
	"managed_principal.manager_invited":         {"invite_id": kindUUID, "role": kindCode, "client_id": kindCode, "expires_at": kindTime},
	"managed_principal.manager_invite_declined": {"invite_id": kindUUID, "manager_principal_id": kindUUID, "role": kindCode},
	"managed_principal.manager_invite_revoked":  {"invite_id": kindUUID},
	"managed_principal.claim_issued":            {"claim_id": kindUUID, "expires_at": kindTime},
	"managed_principal.login_token_issued":      {"client_id": kindCode, "credential_id": kindUUID, "expires_at": kindTime},
	"managed_principal.login_token_revoked":     {"credential_id": kindUUID},
	"managed_principal.session_revoked":         {"kind": kindCode, "session_id": kindUUID},
}

// countKeys are the counts of what deleting a managed principal, or
// revoking all its access, removed.
var countKeys = map[string]kind{
	"invites": kindInt, "relationships": kindInt, "memberships": kindInt, "credentials": kindInt,
	"external_identities": kindInt, "login_sessions": kindInt, "consents": kindInt, "claims": kindInt,
	"oauth_tokens": kindInt, "principal_tokens": kindInt, "login_tokens": kindInt,
}

// details is the allowed, checked part of an event's Details. Mapping
// takes the values it puts into OCSF attributes; what is left goes to
// unmapped.
type details map[string]any

// allowedDetails returns the details of eventType's allowlist that have
// the expected shape, normalized.
func allowedDetails(eventType string, in map[string]any) details {
	keys := allowed[eventType]
	out := details{}
	for k, want := range keys {
		v, ok := in[k]
		if !ok || v == nil {
			continue
		}
		if nv, ok := normalize(want, v); ok {
			out[k] = nv
		}
	}
	return out
}

// take removes key and returns it as a string ("" when absent or not a
// string).
func (d details) take(key string) string {
	v, ok := d[key].(string)
	if !ok {
		return ""
	}
	delete(d, key)
	return v
}

// get returns key as a string without removing it.
func (d details) get(key string) string {
	v, _ := d[key].(string) //nolint:errcheck // a type assertion, not an error: absent and non-string read as ""
	return v
}

func normalize(k kind, v any) (any, bool) {
	ret := func(s string, ok bool) (any, bool) { return s, ok }
	retList := func(l []string, ok bool) (any, bool) { return l, ok }
	switch k {
	case kindCode:
		return ret(code(v))
	case kindCodeList:
		return retList(list(v, code))
	case kindUUID:
		return ret(uuidString(v))
	case kindUUIDList:
		return retList(list(v, uuidString))
	case kindBool:
		b, ok := v.(bool)
		return b, ok
	case kindInt:
		return integer(v)
	case kindTime:
		return timestamp(v)
	case kindManagers:
		return managers(v)
	}
	panic(fmt.Sprintf("ocsfaudit: unknown detail kind %d", k))
}

func code(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		if st, isStringer := v.(fmt.Stringer); isStringer {
			s, ok = st.String(), true
		}
	}
	if !ok || !codePattern.MatchString(s) {
		return "", false
	}
	return s, true
}

func uuidString(v any) (string, bool) {
	switch x := v.(type) {
	case uuid.UUID:
		if x == uuid.Nil {
			return "", false
		}
		return x.String(), true
	case string:
		id, err := uuid.Parse(x)
		if err != nil || id == uuid.Nil {
			return "", false
		}
		return id.String(), true
	}
	return "", false
}

func list(v any, elem func(any) (string, bool)) ([]string, bool) {
	var items []any
	switch x := v.(type) {
	case []string:
		for _, s := range x {
			items = append(items, s)
		}
	case []uuid.UUID:
		for _, id := range x {
			items = append(items, id)
		}
	case []any:
		items = x
	default:
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := elem(it); ok {
			out = append(out, s)
		}
	}
	return out, true
}

func integer(v any) (any, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case uint32:
		return int64(x), true
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			return int64(x), true
		}
	case *int:
		if x != nil {
			return int64(*x), true
		}
	}
	return nil, false
}

func timestamp(v any) (any, bool) {
	switch x := v.(type) {
	case time.Time:
		if x.IsZero() {
			return nil, false
		}
		return x.UTC().Format(time.RFC3339), true
	case *time.Time:
		if x == nil || x.IsZero() {
			return nil, false
		}
		return x.UTC().Format(time.RFC3339), true
	case string:
		t, err := time.Parse(time.RFC3339, x)
		if err != nil {
			return nil, false
		}
		return t.UTC().Format(time.RFC3339), true
	}
	return nil, false
}

// managers keeps the principal ID and role of each manager.
func managers(v any) (any, bool) {
	var in []map[string]any
	switch x := v.(type) {
	case []map[string]string:
		for _, m := range x {
			in = append(in, map[string]any{"principal_id": m["principal_id"], "role": m["role"]})
		}
	case []map[string]any:
		in = x
	case []any:
		for _, it := range x {
			if m, ok := it.(map[string]any); ok {
				in = append(in, m)
			}
		}
	default:
		return nil, false
	}
	out := make([]map[string]string, 0, len(in))
	for _, m := range in {
		id, ok := uuidString(m["principal_id"])
		if !ok {
			continue
		}
		entry := map[string]string{"principal_id": id}
		if role, ok := code(m["role"]); ok {
			entry["role"] = role
		}
		out = append(out, entry)
	}
	return out, true
}
