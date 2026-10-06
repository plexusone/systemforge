// Package storetest is a conformance suite for relying-party stores. Every
// relyingparty.SessionStore and relyingparty.LoginStateStore
// implementation should pass it:
//
//	func TestMyStore(t *testing.T) {
//		storetest.SessionStore(t, func(t *testing.T) relyingparty.SessionStore {
//			return newMyStore(t)
//		})
//	}
package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/relyingparty"
)

// Concurrency is how many goroutines race in the single-use tests.
const Concurrency = 16

func newToken() string { return "tok-" + uuid.NewString() }

// NewSession returns a fully populated, unexpired session for subject.
func NewSession(subject, sid string) relyingparty.Session {
	now := time.Now().UTC().Truncate(time.Second)
	return relyingparty.Session{
		PrincipalID:          "p-" + uuid.NewString(),
		Subject:              subject,
		SID:                  sid,
		Claims:               map[string]any{"sub": subject, "email": "user@example.com", "groups": []any{"a", "b"}},
		AccessToken:          "at-" + uuid.NewString(),
		RefreshToken:         "rt-" + uuid.NewString(),
		IDToken:              "id-" + uuid.NewString(),
		AccessTokenExpiresAt: now.Add(10 * time.Minute),
		CreatedAt:            now,
		ExpiresAt:            now.Add(time.Hour),
	}
}

// AssertSessionEqual fails t unless got and want hold the same values.
// Claims are compared by their JSON form.
func AssertSessionEqual(t *testing.T, got, want relyingparty.Session) {
	t.Helper()
	jsonOf := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal claims: %v", err)
		}
		return string(b)
	}
	if got.PrincipalID != want.PrincipalID || got.Subject != want.Subject || got.SID != want.SID ||
		got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken || got.IDToken != want.IDToken ||
		!got.AccessTokenExpiresAt.Equal(want.AccessTokenExpiresAt) ||
		!got.CreatedAt.Equal(want.CreatedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) ||
		jsonOf(got.Claims) != jsonOf(want.Claims) {
		t.Fatalf("session = %+v\nwant      %+v", got, want)
	}
}

// SessionStore runs the conformance suite against stores created by
// newStore. Each subtest gets a fresh store; stores may share a database
// as the suite uses unique tokens, subjects and SIDs.
func SessionStore(t *testing.T, newStore func(t *testing.T) relyingparty.SessionStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateGetUpdateDelete", func(t *testing.T) {
		s := newStore(t)
		tok := newToken()
		want := NewSession(uuid.NewString(), uuid.NewString())
		if err := s.Create(ctx, tok, want); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := s.Get(ctx, tok)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		AssertSessionEqual(t, got, want)

		want.AccessToken, want.RefreshToken = "at-rotated", "rt-rotated"
		want.AccessTokenExpiresAt = want.AccessTokenExpiresAt.Add(time.Hour)
		if err := s.Update(ctx, tok, want); err != nil {
			t.Fatalf("Update: %v", err)
		}
		got, err = s.Get(ctx, tok)
		if err != nil {
			t.Fatalf("Get after Update: %v", err)
		}
		AssertSessionEqual(t, got, want)

		if err := s.Delete(ctx, tok); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := s.Get(ctx, tok); !errors.Is(err, relyingparty.ErrSessionNotFound) {
			t.Fatalf("Get after Delete err = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("ZeroOptionalFields", func(t *testing.T) {
		s := newStore(t)
		tok := newToken()
		now := time.Now().UTC().Truncate(time.Second)
		want := relyingparty.Session{PrincipalID: "p-" + uuid.NewString(), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := s.Create(ctx, tok, want); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := s.Get(ctx, tok)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !got.AccessTokenExpiresAt.IsZero() || len(got.Claims) != 0 {
			t.Fatalf("zero fields not preserved: %+v", got)
		}
		want.Claims = got.Claims
		AssertSessionEqual(t, got, want)
	})

	t.Run("Unknown", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Get(ctx, newToken()); !errors.Is(err, relyingparty.ErrSessionNotFound) {
			t.Fatalf("Get err = %v, want ErrSessionNotFound", err)
		}
		if err := s.Update(ctx, newToken(), NewSession("x", "")); !errors.Is(err, relyingparty.ErrSessionNotFound) {
			t.Fatalf("Update err = %v, want ErrSessionNotFound", err)
		}
		if err := s.Delete(ctx, newToken()); err != nil {
			t.Fatalf("Delete unknown: %v", err)
		}
	})

	t.Run("Expired", func(t *testing.T) {
		s := newStore(t)
		tok := newToken()
		sess := NewSession(uuid.NewString(), "")
		sess.CreatedAt = sess.CreatedAt.Add(-2 * time.Hour)
		sess.ExpiresAt = time.Now().Add(-time.Minute)
		if err := s.Create(ctx, tok, sess); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := s.Get(ctx, tok); !errors.Is(err, relyingparty.ErrSessionNotFound) {
			t.Fatalf("Get expired err = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("DeleteBySubjectAndSID", func(t *testing.T) {
		s := newStore(t)
		subA, subB := uuid.NewString(), uuid.NewString()
		sid1, sid2 := uuid.NewString(), uuid.NewString()
		toks := map[string]relyingparty.Session{
			newToken(): NewSession(subA, sid1),
			newToken(): NewSession(subA, sid2),
			newToken(): NewSession(subB, sid2),
			newToken(): NewSession(subB, ""),
		}
		for tok, sess := range toks {
			if err := s.Create(ctx, tok, sess); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}
		if n, err := s.DeleteBySubject(ctx, ""); err != nil || n != 0 {
			t.Fatalf("DeleteBySubject(\"\") = %d, %v; want 0", n, err)
		}
		if n, err := s.DeleteBySID(ctx, ""); err != nil || n != 0 {
			t.Fatalf("DeleteBySID(\"\") = %d, %v; want 0", n, err)
		}
		if n, err := s.DeleteBySID(ctx, sid2); err != nil || n != 2 {
			t.Fatalf("DeleteBySID = %d, %v; want 2", n, err)
		}
		if n, err := s.DeleteBySubject(ctx, subA); err != nil || n != 1 {
			t.Fatalf("DeleteBySubject(a) = %d, %v; want 1", n, err)
		}
		left := 0
		for tok := range toks {
			if _, err := s.Get(ctx, tok); err == nil {
				left++
			}
		}
		if left != 1 {
			t.Fatalf("%d sessions left, want 1 (subject b without sid)", left)
		}
	})

	t.Run("ConcurrentUse", func(t *testing.T) {
		s := newStore(t)
		var wg sync.WaitGroup
		errs := make(chan error, Concurrency)
		for range Concurrency {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tok := newToken()
				sess := NewSession(uuid.NewString(), "")
				if err := s.Create(ctx, tok, sess); err != nil {
					errs <- err
					return
				}
				got, err := s.Get(ctx, tok)
				if err != nil {
					errs <- err
					return
				}
				if got.RefreshToken != sess.RefreshToken {
					errs <- errors.New("session mixed up between tokens")
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("concurrent use: %v", err)
		}
	})
}

// LoginStateStore runs the conformance suite against stores created by
// newStore.
func LoginStateStore(t *testing.T, newStore func(t *testing.T) relyingparty.LoginStateStore) {
	t.Helper()
	ctx := context.Background()
	newState := func() relyingparty.LoginState {
		return relyingparty.LoginState{
			Nonce:     "n-" + uuid.NewString(),
			Verifier:  "v-" + uuid.NewString(),
			ReturnTo:  "https://app.example.com/after",
			ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(10 * time.Minute),
		}
	}

	t.Run("PutTakeSingleUse", func(t *testing.T) {
		s := newStore(t)
		st, want := newToken(), newState()
		if err := s.Put(ctx, st, want); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Take(ctx, st)
		if err != nil {
			t.Fatalf("Take: %v", err)
		}
		if got.Nonce != want.Nonce || got.Verifier != want.Verifier || got.ReturnTo != want.ReturnTo || !got.ExpiresAt.Equal(want.ExpiresAt) {
			t.Fatalf("Take = %+v, want %+v", got, want)
		}
		if _, err := s.Take(ctx, st); !errors.Is(err, relyingparty.ErrInvalidState) {
			t.Fatalf("second Take err = %v, want ErrInvalidState", err)
		}
	})

	t.Run("Unknown", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Take(ctx, newToken()); !errors.Is(err, relyingparty.ErrInvalidState) {
			t.Fatalf("Take err = %v, want ErrInvalidState", err)
		}
	})

	t.Run("Expired", func(t *testing.T) {
		s := newStore(t)
		st, data := newToken(), newState()
		data.ExpiresAt = time.Now().Add(-time.Second)
		if err := s.Put(ctx, st, data); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if _, err := s.Take(ctx, st); !errors.Is(err, relyingparty.ErrInvalidState) {
			t.Fatalf("Take expired err = %v, want ErrInvalidState", err)
		}
	})

	t.Run("ConcurrentTake", func(t *testing.T) {
		s := newStore(t)
		st, want := newToken(), newState()
		if err := s.Put(ctx, st, want); err != nil {
			t.Fatalf("Put: %v", err)
		}
		var (
			wg    sync.WaitGroup
			mu    sync.Mutex
			wins  []relyingparty.LoginState
			other []error
			start = make(chan struct{})
		)
		for range Concurrency {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				got, err := s.Take(ctx, st)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					wins = append(wins, got)
				case !errors.Is(err, relyingparty.ErrInvalidState):
					other = append(other, err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if len(wins) != 1 || len(other) > 0 {
			t.Fatalf("concurrent Take: %d successes (want 1), unexpected errors %v", len(wins), other)
		}
		if wins[0].Verifier != want.Verifier {
			t.Fatalf("winner got %+v", wins[0])
		}
	})
}
