package relyingparty

import (
	"encoding/json"
	"testing"
	"time"
)

func TestIdentityFromClaimsEmailVerifiedAt(t *testing.T) {
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	idt := idToken("p1", map[string]any{})
	idt.Email, idt.EmailVerified, idt.EmailVerifiedAt = "a@example.com", true, at.Unix()
	id, err := IdentityFromClaims(idt, nil)
	if err != nil || !id.EmailVerifiedAt.Equal(at) {
		t.Fatalf("from ID token = %+v, %v", id, err)
	}

	// UserInfo is fresher: a changed address carries its own time.
	later := at.Add(time.Hour)
	id, err = IdentityFromClaims(idt, &UserInfo{Subject: "p1", Email: "b@example.com", EmailVerified: true, EmailVerifiedAt: later.Unix()})
	if err != nil || id.Email != "b@example.com" || !id.EmailVerifiedAt.Equal(later) {
		t.Fatalf("from userinfo = %+v, %v", id, err)
	}

	// The time counts only with email_verified.
	idt.EmailVerified = false
	if id, err := IdentityFromClaims(idt, nil); err != nil || !id.EmailVerifiedAt.IsZero() {
		t.Fatalf("unverified = %+v, %v; want no time", id, err)
	}
	// Absent: zero.
	if id, err := IdentityFromClaims(idToken("p2", map[string]any{}), nil); err != nil || !id.EmailVerifiedAt.IsZero() {
		t.Fatalf("absent = %+v, %v", id, err)
	}

	var info UserInfo
	if err := json.Unmarshal([]byte(`{"sub":"p1","email_verified":true,"email_verified_at":1772366400}`), &info); err != nil || info.EmailVerifiedAt != 1772366400 {
		t.Fatalf("decoding userinfo = %+v, %v", info, err)
	}
}
