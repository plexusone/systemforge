// Package storetest is a conformance suite for SystemAuth social login
// stores. Every LoginSessionStore, oauthclient.StateStore, ConsentStore and
// VerificationTokenStore implementation should pass it:
//
//	func TestMyStore(t *testing.T) {
//		storetest.LoginSessionStore(t, func(t *testing.T) systemauth.LoginSessionStore {
//			return newMyStore(t)
//		})
//	}
package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/oauthclient"
	"github.com/plexusone/systemforge/identity/systemauth"
)

// Concurrency is how many goroutines race in the single-use tests.
const Concurrency = 16

func newToken() string {
	return "tok-" + uuid.NewString()
}

// LoginSessionStore runs the conformance suite against stores created by
// newStore. Each subtest gets a fresh store.
func LoginSessionStore(t *testing.T, newStore func(t *testing.T) systemauth.LoginSessionStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("CreateGetDelete", func(t *testing.T) {
		s := newStore(t)
		tok := newToken()
		want := systemauth.LoginSession{
			PrincipalID: uuid.New(),
			Provider:    "github",
			CreatedAt:   now,
			ExpiresAt:   now.Add(time.Hour),
		}
		if err := s.Create(ctx, tok, want); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := s.Get(ctx, tok)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.PrincipalID != want.PrincipalID || got.Provider != want.Provider ||
			!got.CreatedAt.Equal(want.CreatedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
			t.Fatalf("Get = %+v, want %+v", got, want)
		}
		if err := s.Delete(ctx, tok); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := s.Get(ctx, tok); !errors.Is(err, systemauth.ErrLoginSessionNotFound) {
			t.Fatalf("Get after Delete err = %v, want ErrLoginSessionNotFound", err)
		}
	})

	t.Run("UnknownToken", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Get(ctx, newToken()); !errors.Is(err, systemauth.ErrLoginSessionNotFound) {
			t.Fatalf("Get err = %v, want ErrLoginSessionNotFound", err)
		}
		if err := s.Delete(ctx, newToken()); err != nil {
			t.Fatalf("Delete unknown: %v", err)
		}
	})

	t.Run("Expired", func(t *testing.T) {
		s := newStore(t)
		tok := newToken()
		err := s.Create(ctx, tok, systemauth.LoginSession{
			PrincipalID: uuid.New(),
			CreatedAt:   now.Add(-2 * time.Hour),
			ExpiresAt:   now.Add(-time.Hour),
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := s.Get(ctx, tok); !errors.Is(err, systemauth.ErrLoginSessionNotFound) {
			t.Fatalf("Get expired err = %v, want ErrLoginSessionNotFound", err)
		}
	})

	t.Run("Isolation", func(t *testing.T) {
		s := newStore(t)
		a, b := newToken(), newToken()
		pa, pb := uuid.New(), uuid.New()
		for tok, p := range map[string]uuid.UUID{a: pa, b: pb} {
			if err := s.Create(ctx, tok, systemauth.LoginSession{PrincipalID: p, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}
		if err := s.Delete(ctx, a); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got, err := s.Get(ctx, b)
		if err != nil || got.PrincipalID != pb {
			t.Fatalf("Get other session = %+v, %v", got, err)
		}
	})
}

// StateStore runs the conformance suite for oauthclient.StateStore
// implementations used as SystemAuth login state stores.
func StateStore(t *testing.T, newStore func(t *testing.T) oauthclient.StateStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("PutTakeSingleUse", func(t *testing.T) {
		s := newStore(t)
		state := newToken()
		want := oauthclient.StateData{
			Provider:     "google",
			RedirectURL:  "https://app.example.com/after",
			Nonce:        "n-123",
			PKCEVerifier: "v-456",
		}
		if err := s.Put(ctx, state, want, time.Minute); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Take(ctx, state)
		if err != nil {
			t.Fatalf("Take: %v", err)
		}
		if got != want {
			t.Fatalf("Take = %+v, want %+v", got, want)
		}
		if _, err := s.Take(ctx, state); !errors.Is(err, oauthclient.ErrInvalidState) {
			t.Fatalf("second Take err = %v, want ErrInvalidState", err)
		}
	})

	t.Run("Unknown", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Take(ctx, newToken()); !errors.Is(err, oauthclient.ErrInvalidState) {
			t.Fatalf("Take err = %v, want ErrInvalidState", err)
		}
	})

	t.Run("EmptyState", func(t *testing.T) {
		s := newStore(t)
		if err := s.Put(ctx, "", oauthclient.StateData{Provider: "github"}, time.Minute); err == nil {
			t.Fatal("Put with empty state succeeded")
		}
	})

	t.Run("Expired", func(t *testing.T) {
		s := newStore(t)
		state := newToken()
		if err := s.Put(ctx, state, oauthclient.StateData{Provider: "github"}, -time.Second); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if _, err := s.Take(ctx, state); !errors.Is(err, oauthclient.ErrInvalidState) {
			t.Fatalf("Take expired err = %v, want ErrInvalidState", err)
		}
	})

	t.Run("ConcurrentTake", func(t *testing.T) {
		s := newStore(t)
		state := newToken()
		if err := s.Put(ctx, state, oauthclient.StateData{Provider: "github"}, time.Minute); err != nil {
			t.Fatalf("Put: %v", err)
		}
		ok, errs := race(Concurrency, func() error {
			_, err := s.Take(ctx, state)
			return err
		}, oauthclient.ErrInvalidState)
		if ok != 1 || len(errs) > 0 {
			t.Fatalf("concurrent Take: %d successes (want 1), unexpected errors %v", ok, errs)
		}
	})
}

// ConsentStore runs the conformance suite against stores created by
// newStore.
func ConsentStore(t *testing.T, newStore func(t *testing.T) systemauth.ConsentStore) {
	t.Helper()
	ctx := context.Background()

	has := func(t *testing.T, s systemauth.ConsentStore, p, c string, scopes ...string) bool {
		t.Helper()
		ok, err := s.HasConsent(ctx, p, c, scopes)
		if err != nil {
			t.Fatalf("HasConsent: %v", err)
		}
		return ok
	}

	t.Run("SaveMergeRevoke", func(t *testing.T) {
		s := newStore(t)
		p, c := uuid.NewString(), "client-a"
		if has(t, s, p, c, "openid") {
			t.Fatal("consent before save")
		}
		if err := s.SaveConsent(ctx, p, c, []string{"openid", "profile"}); err != nil {
			t.Fatalf("SaveConsent: %v", err)
		}
		if !has(t, s, p, c, "openid", "profile") || !has(t, s, p, c, "profile") {
			t.Fatal("granted scopes not found")
		}
		if has(t, s, p, c, "openid", "email") {
			t.Fatal("ungranted scope reported as granted")
		}
		// Saving again merges and tolerates duplicates.
		if err := s.SaveConsent(ctx, p, c, []string{"email", "openid", "email"}); err != nil {
			t.Fatalf("SaveConsent merge: %v", err)
		}
		if !has(t, s, p, c, "openid", "profile", "email") {
			t.Fatal("merged scopes not found")
		}
		if !has(t, s, p, c, "openid", "openid") {
			t.Fatal("duplicate requested scopes not handled")
		}
		if err := s.RevokeConsent(ctx, p, c); err != nil {
			t.Fatalf("RevokeConsent: %v", err)
		}
		if has(t, s, p, c, "openid") {
			t.Fatal("consent after revoke")
		}
		if err := s.RevokeConsent(ctx, p, c); err != nil {
			t.Fatalf("RevokeConsent unknown: %v", err)
		}
	})

	t.Run("Isolation", func(t *testing.T) {
		s := newStore(t)
		p1, p2 := uuid.NewString(), uuid.NewString()
		if err := s.SaveConsent(ctx, p1, "client-a", []string{"openid"}); err != nil {
			t.Fatalf("SaveConsent: %v", err)
		}
		if has(t, s, p2, "client-a", "openid") || has(t, s, p1, "client-b", "openid") {
			t.Fatal("consent leaked to another principal or client")
		}
		if err := s.SaveConsent(ctx, p1, "client-b", []string{"openid"}); err != nil {
			t.Fatalf("SaveConsent: %v", err)
		}
		if err := s.RevokeConsent(ctx, p1, "client-a"); err != nil {
			t.Fatalf("RevokeConsent: %v", err)
		}
		if !has(t, s, p1, "client-b", "openid") {
			t.Fatal("revoke removed another client's consent")
		}
	})

	t.Run("ConcurrentSave", func(t *testing.T) {
		s := newStore(t)
		p := uuid.NewString()
		var wg sync.WaitGroup
		errs := make(chan error, Concurrency)
		for i := range Concurrency {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- s.SaveConsent(ctx, p, "client-a", []string{"openid", fmt.Sprintf("scope-%d", i)})
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent SaveConsent: %v", err)
			}
		}
		want := []string{"openid"}
		for i := range Concurrency {
			want = append(want, fmt.Sprintf("scope-%d", i))
		}
		if !has(t, s, p, "client-a", want...) {
			t.Fatal("concurrent grants were lost")
		}
	})
}

// VerificationTokenStore runs the conformance suite against stores created
// by newStore. Each subtest gets a fresh store.
func VerificationTokenStore(t *testing.T, newStore func(t *testing.T) systemauth.VerificationTokenStore) {
	t.Helper()
	ctx := context.Background()
	binding := func() string { return "login:" + uuid.NewString() }
	create := func(t *testing.T, s systemauth.VerificationTokenStore, tok string, vt systemauth.VerificationToken) {
		t.Helper()
		if err := s.Create(ctx, tok, vt); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	wantInvalid := func(t *testing.T, s systemauth.VerificationTokenStore, tok string, purpose systemauth.VerificationPurpose, b, what string) {
		t.Helper()
		if _, err := s.Consume(ctx, tok, purpose, b); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("Consume %s err = %v, want ErrVerificationTokenInvalid", what, err)
		}
	}

	t.Run("CreateConsumeSingleUse", func(t *testing.T) {
		s := newStore(t)
		tok, b, pid := newToken(), binding(), uuid.New()
		data := []byte(`{"k":"v"}`)
		create(t, s, tok, systemauth.VerificationToken{
			Purpose:     systemauth.PurposeEmailChange,
			Email:       "new@example.com",
			PrincipalID: pid,
			Binding:     b,
			Data:        data,
		})
		got, err := s.Consume(ctx, tok, systemauth.PurposeEmailChange, b)
		if err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if got.Email != "new@example.com" || got.PrincipalID != pid || got.Binding != b ||
			string(got.Data) != string(data) || got.Purpose != systemauth.PurposeEmailChange {
			t.Fatalf("Consume = %+v", got)
		}
		if got.ConsumedAt == nil {
			t.Fatal("Consume returned a token without ConsumedAt")
		}
		if d := got.ExpiresAt.Sub(got.CreatedAt); d != systemauth.DefaultVerificationTokenTTL {
			t.Fatalf("default lifetime = %v, want %v", d, systemauth.DefaultVerificationTokenTTL)
		}
		wantInvalid(t, s, tok, systemauth.PurposeEmailChange, b, "a second time")
	})

	t.Run("NoPrincipal", func(t *testing.T) {
		s := newStore(t)
		tok, b := newToken(), binding()
		create(t, s, tok, systemauth.VerificationToken{Purpose: systemauth.PurposeVerifyEmail, Email: "a@example.com", Binding: b})
		got, err := s.Consume(ctx, tok, systemauth.PurposeVerifyEmail, b)
		if err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if got.PrincipalID != uuid.Nil || len(got.Data) != 0 {
			t.Fatalf("Consume = %+v, want no principal and no data", got)
		}
	})

	t.Run("WrongPurposeOrBindingLeavesTokenUsable", func(t *testing.T) {
		s := newStore(t)
		tok, b := newToken(), binding()
		create(t, s, tok, systemauth.VerificationToken{Purpose: systemauth.PurposeVerifyEmail, Email: "a@example.com", Binding: b})
		wantInvalid(t, s, tok, systemauth.PurposeEmailChange, b, "for another purpose")
		wantInvalid(t, s, tok, systemauth.PurposeVerifyEmail, binding(), "with another binding")
		wantInvalid(t, s, tok, systemauth.PurposeVerifyEmail, "", "with no binding")
		if _, err := s.Consume(ctx, tok, systemauth.PurposeVerifyEmail, b); err != nil {
			t.Fatalf("Consume by the owner after failed attempts: %v", err)
		}
	})

	t.Run("Unknown", func(t *testing.T) {
		s := newStore(t)
		wantInvalid(t, s, newToken(), systemauth.PurposeVerifyEmail, binding(), "an unknown token")
	})

	t.Run("InvalidCreate", func(t *testing.T) {
		s := newStore(t)
		for name, tc := range map[string]struct {
			token string
			vt    systemauth.VerificationToken
		}{
			"empty token":     {"", systemauth.VerificationToken{Purpose: systemauth.PurposeVerifyEmail, Email: "a@example.com", Binding: "b"}},
			"unknown purpose": {newToken(), systemauth.VerificationToken{Purpose: "sign_in", Email: "a@example.com", Binding: "b"}},
			"no email":        {newToken(), systemauth.VerificationToken{Purpose: systemauth.PurposeVerifyEmail, Binding: "b"}},
			"no binding":      {newToken(), systemauth.VerificationToken{Purpose: systemauth.PurposeVerifyEmail, Email: "a@example.com"}},
		} {
			if err := s.Create(ctx, tc.token, tc.vt); err == nil {
				t.Fatalf("Create with %s succeeded", name)
			}
		}
	})

	t.Run("Expired", func(t *testing.T) {
		s := newStore(t)
		tok, b := newToken(), binding()
		now := time.Now()
		create(t, s, tok, systemauth.VerificationToken{
			Purpose: systemauth.PurposeVerifyEmail, Email: "a@example.com", Binding: b,
			CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Second),
		})
		wantInvalid(t, s, tok, systemauth.PurposeVerifyEmail, b, "an expired token")
		if _, err := s.Latest(ctx, systemauth.PurposeVerifyEmail, b); !errors.Is(err, systemauth.ErrVerificationTokenNotFound) {
			t.Fatalf("Latest expired err = %v, want ErrVerificationTokenNotFound", err)
		}
	})

	t.Run("RecordAttemptLimit", func(t *testing.T) {
		s := newStore(t)
		b := binding()
		create(t, s, newToken(), systemauth.VerificationToken{Purpose: systemauth.PurposeSignInCode, Email: "a@example.com", Binding: b})
		for i := 1; i <= 3; i++ {
			got, err := s.RecordAttempt(ctx, systemauth.PurposeSignInCode, b, 3)
			if err != nil {
				t.Fatalf("RecordAttempt %d: %v", i, err)
			}
			if got.Attempts != i {
				t.Fatalf("RecordAttempt %d: Attempts = %d, want %d", i, got.Attempts, i)
			}
		}
		if _, err := s.RecordAttempt(ctx, systemauth.PurposeSignInCode, b, 3); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("RecordAttempt past the limit err = %v, want ErrVerificationTokenInvalid", err)
		}
		if got, err := s.Latest(ctx, systemauth.PurposeSignInCode, b); err != nil || got.Attempts != 3 {
			t.Fatalf("Latest after the limit = %+v, %v; want Attempts 3 (a refused attempt changes nothing)", got, err)
		}
	})

	t.Run("RecordAttemptScope", func(t *testing.T) {
		s := newStore(t)
		b := binding()
		if _, err := s.RecordAttempt(ctx, systemauth.PurposeSignInCode, b, 3); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("RecordAttempt without a token err = %v, want ErrVerificationTokenInvalid", err)
		}
		create(t, s, newToken(), systemauth.VerificationToken{Purpose: systemauth.PurposeSignInCode, Email: "a@example.com", Binding: b})
		if _, err := s.RecordAttempt(ctx, systemauth.PurposeVerifyEmail, b, 3); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("RecordAttempt for another purpose err = %v, want ErrVerificationTokenInvalid", err)
		}
		if _, err := s.RecordAttempt(ctx, systemauth.PurposeSignInCode, binding(), 3); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("RecordAttempt for another binding err = %v, want ErrVerificationTokenInvalid", err)
		}
		if _, err := s.RecordAttempt(ctx, systemauth.PurposeSignInCode, b, 0); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("RecordAttempt with no limit err = %v, want ErrVerificationTokenInvalid", err)
		}
		// Refused attempts did not touch the token.
		if got, err := s.Latest(ctx, systemauth.PurposeSignInCode, b); err != nil || got.Attempts != 0 {
			t.Fatalf("Latest = %+v, %v; want Attempts 0", got, err)
		}
	})

	t.Run("RecordAttemptTargetsNewestAndUsable", func(t *testing.T) {
		s := newStore(t)
		b := binding()
		now := time.Now().UTC().Truncate(time.Second)
		old, newer := newToken(), newToken()
		create(t, s, old, systemauth.VerificationToken{
			Purpose: systemauth.PurposeSignInCode, Email: "a@example.com", Binding: b,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		})
		create(t, s, newer, systemauth.VerificationToken{
			Purpose: systemauth.PurposeSignInCode, Email: "a@example.com", Binding: b,
			CreatedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Hour),
		})
		got, err := s.RecordAttempt(ctx, systemauth.PurposeSignInCode, b, 3)
		if err != nil || got.Attempts != 1 || !got.CreatedAt.Equal(now.Add(time.Second)) {
			t.Fatalf("RecordAttempt = %+v, %v; want the newest token", got, err)
		}
		if _, err := s.Revoke(ctx, systemauth.PurposeSignInCode, b); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if _, err := s.RecordAttempt(ctx, systemauth.PurposeSignInCode, b, 3); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("RecordAttempt after Revoke err = %v, want ErrVerificationTokenInvalid", err)
		}
	})

	t.Run("RecordAttemptConcurrent", func(t *testing.T) {
		s := newStore(t)
		b := binding()
		create(t, s, newToken(), systemauth.VerificationToken{Purpose: systemauth.PurposeSignInCode, Email: "a@example.com", Binding: b})
		const guesses, limit = 20, 5
		ok, errs := race(guesses, func() error {
			_, err := s.RecordAttempt(ctx, systemauth.PurposeSignInCode, b, limit)
			return err
		}, systemauth.ErrVerificationTokenInvalid)
		if len(errs) != 0 {
			t.Fatalf("%d concurrent guesses failed with errors other than ErrVerificationTokenInvalid: %v", len(errs), errs)
		}
		if ok != limit {
			t.Fatalf("%d concurrent guesses counted %d attempts, want exactly %d", guesses, ok, limit)
		}
		if got, err := s.Latest(ctx, systemauth.PurposeSignInCode, b); err != nil || got.Attempts != limit {
			t.Fatalf("Latest after the race = %+v, %v; want Attempts %d", got, err, limit)
		}
	})

	t.Run("ConsumeTokenExactRow", func(t *testing.T) {
		s := newStore(t)
		b := binding()
		now := time.Now().UTC().Truncate(time.Second)
		create(t, s, newToken(), systemauth.VerificationToken{
			Purpose: systemauth.PurposeSignInCode, Email: "a@example.com", Binding: b,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		})
		old, err := s.Latest(ctx, systemauth.PurposeSignInCode, b)
		if err != nil {
			t.Fatalf("Latest: %v", err)
		}
		create(t, s, newToken(), systemauth.VerificationToken{
			Purpose: systemauth.PurposeSignInCode, Email: "a@example.com", Binding: b,
			CreatedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Hour),
		})
		newest, err := s.Latest(ctx, systemauth.PurposeSignInCode, b)
		if err != nil || newest.ID == old.ID {
			t.Fatalf("Latest = %+v, %v; want the newer row", newest, err)
		}
		if err := s.ConsumeToken(ctx, old.ID, systemauth.PurposeVerifyEmail, b); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("ConsumeToken for another purpose err = %v, want ErrVerificationTokenInvalid", err)
		}
		if err := s.ConsumeToken(ctx, old.ID, systemauth.PurposeSignInCode, binding()); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("ConsumeToken for another binding err = %v, want ErrVerificationTokenInvalid", err)
		}
		if err := s.ConsumeToken(ctx, uuid.New(), systemauth.PurposeSignInCode, b); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("ConsumeToken for an unknown row err = %v, want ErrVerificationTokenInvalid", err)
		}
		// A row that a newer one replaced is dead, usable or not: refusing it
		// leaves the replacement alone.
		if err := s.ConsumeToken(ctx, old.ID, systemauth.PurposeSignInCode, b); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("ConsumeToken of a replaced row err = %v, want ErrVerificationTokenInvalid", err)
		}
		if got, err := s.Latest(ctx, systemauth.PurposeSignInCode, b); err != nil || got.ID != newest.ID {
			t.Fatalf("Latest after = %+v, %v; want the newer row still usable", got, err)
		}
		if err := s.ConsumeToken(ctx, newest.ID, systemauth.PurposeSignInCode, b); err != nil {
			t.Fatalf("ConsumeToken of the newest row: %v", err)
		}
		if err := s.ConsumeToken(ctx, newest.ID, systemauth.PurposeSignInCode, b); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("ConsumeToken a second time err = %v, want ErrVerificationTokenInvalid", err)
		}
		// Using the newest row does not bring the replaced one back.
		if err := s.ConsumeToken(ctx, old.ID, systemauth.PurposeSignInCode, b); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
			t.Fatalf("ConsumeToken of a replaced row after its replacement was used err = %v, want ErrVerificationTokenInvalid", err)
		}
	})

	t.Run("SameInstantFollowsIssueOrder", func(t *testing.T) {
		// A coarse clock (Windows') gives a resend the same time as the code it
		// replaces. The order must still be the order of issue, or a
		// replacement could be treated as the older code.
		for range 20 {
			s := newStore(t)
			b := binding()
			at := time.Now().UTC().Truncate(time.Second)
			var firstID uuid.UUID
			for i := range 2 {
				create(t, s, newToken(), systemauth.VerificationToken{
					Purpose: systemauth.PurposeSignInCode, Email: fmt.Sprintf("a%d@example.com", i), Binding: b,
					CreatedAt: at, ExpiresAt: at.Add(time.Hour),
				})
				if i == 0 {
					row, err := s.Latest(ctx, systemauth.PurposeSignInCode, b)
					if err != nil {
						t.Fatalf("Latest: %v", err)
					}
					firstID = row.ID
				}
			}
			got, err := s.Latest(ctx, systemauth.PurposeSignInCode, b)
			if err != nil || got.Email != "a1@example.com" {
				t.Fatalf("Latest = %+v, %v; want the token issued second", got, err)
			}
			counted, err := s.RecordAttempt(ctx, systemauth.PurposeSignInCode, b, 3)
			if err != nil || counted.Email != "a1@example.com" {
				t.Fatalf("RecordAttempt counted %+v, %v; want the token issued second", counted, err)
			}
			if err := s.ConsumeToken(ctx, firstID, systemauth.PurposeSignInCode, b); !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
				t.Fatalf("ConsumeToken of the token issued first err = %v, want ErrVerificationTokenInvalid", err)
			}
			if err := s.ConsumeToken(ctx, got.ID, systemauth.PurposeSignInCode, b); err != nil {
				t.Fatalf("ConsumeToken of the token issued second: %v", err)
			}
		}
	})

	t.Run("ConsumeTokenOnlyAgainstItsOwnBinding", func(t *testing.T) {
		// A newer token of another binding or purpose does not replace this one.
		s := newStore(t)
		b, other := binding(), binding()
		now := time.Now().UTC().Truncate(time.Second)
		create(t, s, newToken(), systemauth.VerificationToken{
			Purpose: systemauth.PurposeSignInCode, Email: "a@example.com", Binding: b,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		})
		create(t, s, newToken(), systemauth.VerificationToken{
			Purpose: systemauth.PurposeSignInCode, Email: "b@example.com", Binding: other,
			CreatedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Hour),
		})
		create(t, s, newToken(), systemauth.VerificationToken{
			Purpose: systemauth.PurposeVerifyEmail, Email: "a@example.com", Binding: b,
			CreatedAt: now.Add(2 * time.Second), ExpiresAt: now.Add(time.Hour),
		})
		row, err := s.Latest(ctx, systemauth.PurposeSignInCode, b)
		if err != nil {
			t.Fatalf("Latest: %v", err)
		}
		if err := s.ConsumeToken(ctx, row.ID, systemauth.PurposeSignInCode, b); err != nil {
			t.Fatalf("ConsumeToken: %v", err)
		}
	})

	t.Run("ConsumeTokenOnceConcurrently", func(t *testing.T) {
		s := newStore(t)
		b := binding()
		create(t, s, newToken(), systemauth.VerificationToken{Purpose: systemauth.PurposeSignInCode, Email: "a@example.com", Binding: b})
		row, err := s.Latest(ctx, systemauth.PurposeSignInCode, b)
		if err != nil {
			t.Fatalf("Latest: %v", err)
		}
		ok, errs := race(Concurrency, func() error {
			return s.ConsumeToken(ctx, row.ID, systemauth.PurposeSignInCode, b)
		}, systemauth.ErrVerificationTokenInvalid)
		if len(errs) != 0 || ok != 1 {
			t.Fatalf("%d concurrent calls: %d succeeded, unexpected errors %v; want exactly 1", Concurrency, ok, errs)
		}
	})

	t.Run("RecordAttemptReturnsItsOwnCount", func(t *testing.T) {
		// Each counted call must be handed the count its own increment made,
		// so that exactly one call sees the last try. Counts read back after
		// another call's increment would repeat.
		s := newStore(t)
		b := binding()
		create(t, s, newToken(), systemauth.VerificationToken{Purpose: systemauth.PurposeSignInCode, Email: "a@example.com", Binding: b})
		const guesses, limit = 20, 5
		var (
			mu     sync.Mutex
			counts []int
			wg     sync.WaitGroup
		)
		for range guesses {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := s.RecordAttempt(ctx, systemauth.PurposeSignInCode, b, limit)
				if err != nil {
					if !errors.Is(err, systemauth.ErrVerificationTokenInvalid) {
						t.Errorf("RecordAttempt: %v", err)
					}
					return
				}
				mu.Lock()
				counts = append(counts, got.Attempts)
				mu.Unlock()
			}()
		}
		wg.Wait()
		seen := map[int]int{}
		for _, c := range counts {
			seen[c]++
		}
		for want := 1; want <= limit; want++ {
			if seen[want] != 1 {
				t.Fatalf("counts handed back = %v, want each of 1..%d exactly once", counts, limit)
			}
		}
		if len(counts) != limit {
			t.Fatalf("%d calls were counted, want %d: %v", len(counts), limit, counts)
		}
	})

	t.Run("LatestAndRevoke", func(t *testing.T) {
		s := newStore(t)
		b, other := binding(), binding()
		now := time.Now().UTC().Truncate(time.Second)
		first, second, third := newToken(), newToken(), newToken()
		for i, tok := range []string{first, second} {
			create(t, s, tok, systemauth.VerificationToken{
				Purpose: systemauth.PurposeVerifyEmail, Email: fmt.Sprintf("a%d@example.com", i), Binding: b,
				CreatedAt: now.Add(time.Duration(i) * time.Second), ExpiresAt: now.Add(time.Hour),
			})
		}
		create(t, s, third, systemauth.VerificationToken{Purpose: systemauth.PurposeVerifyEmail, Email: "other@example.com", Binding: other})
		got, err := s.Latest(ctx, systemauth.PurposeVerifyEmail, b)
		if err != nil {
			t.Fatalf("Latest: %v", err)
		}
		if got.Email != "a1@example.com" {
			t.Fatalf("Latest email = %q, want the newest token's", got.Email)
		}
		if _, err := s.Latest(ctx, systemauth.PurposeEmailChange, b); !errors.Is(err, systemauth.ErrVerificationTokenNotFound) {
			t.Fatalf("Latest for another purpose err = %v, want ErrVerificationTokenNotFound", err)
		}
		n, err := s.Revoke(ctx, systemauth.PurposeVerifyEmail, b)
		if err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if n != 2 {
			t.Fatalf("Revoke = %d, want 2", n)
		}
		wantInvalid(t, s, first, systemauth.PurposeVerifyEmail, b, "a revoked token")
		wantInvalid(t, s, second, systemauth.PurposeVerifyEmail, b, "a revoked token")
		if _, err := s.Latest(ctx, systemauth.PurposeVerifyEmail, b); !errors.Is(err, systemauth.ErrVerificationTokenNotFound) {
			t.Fatalf("Latest after Revoke err = %v, want ErrVerificationTokenNotFound", err)
		}
		if _, err := s.Consume(ctx, third, systemauth.PurposeVerifyEmail, other); err != nil {
			t.Fatalf("Revoke touched another binding's token: %v", err)
		}
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := newStore(t)
		now := time.Now()
		live, b := newToken(), binding()
		create(t, s, newToken(), systemauth.VerificationToken{
			Purpose: systemauth.PurposeVerifyEmail, Email: "a@example.com", Binding: binding(),
			CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute),
		})
		create(t, s, live, systemauth.VerificationToken{Purpose: systemauth.PurposeVerifyEmail, Email: "a@example.com", Binding: b})
		if _, err := s.DeleteExpired(ctx); err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}
		if _, err := s.Consume(ctx, live, systemauth.PurposeVerifyEmail, b); err != nil {
			t.Fatalf("DeleteExpired removed a live token: %v", err)
		}
	})

	t.Run("ConcurrentConsume", func(t *testing.T) {
		s := newStore(t)
		tok, b := newToken(), binding()
		create(t, s, tok, systemauth.VerificationToken{Purpose: systemauth.PurposeVerifyEmail, Email: "a@example.com", Binding: b})
		ok, errs := race(Concurrency, func() error {
			_, err := s.Consume(ctx, tok, systemauth.PurposeVerifyEmail, b)
			return err
		}, systemauth.ErrVerificationTokenInvalid)
		if ok != 1 || len(errs) > 0 {
			t.Fatalf("concurrent Consume: %d successes (want 1), unexpected errors %v", ok, errs)
		}
	})
}

// race runs fn concurrently n times. It returns how many calls succeeded
// and the errors that were not expected.
func race(n int, fn func() error, expected error) (int, []error) {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		ok    int
		other []error
		start = make(chan struct{})
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := fn()
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case !errors.Is(err, expected):
				other = append(other, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	return ok, other
}
