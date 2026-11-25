package systemauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexusone/systemforge/contract/audit"
)

func TestEmailSignInEvents(t *testing.T) {
	events := &eventCapture{}
	s, sender := newEmailLoginServer(t, nil, nil, nil, WithAuditEmitter(events))

	_, cookie := requestCode(t, s, "jane.doe@example.com")
	code := lastCode(t, sender)

	sent := events.find(EventEmailCodeSent, "")
	if len(sent) != 1 || sent[0].Details["sent"] != true {
		t.Fatalf("code sent events = %+v, want one with sent true", sent)
	}

	submitCode(s, cookie, wrongCode(code))
	refused := events.find(EventSignIn, audit.OutcomeFailure)
	if len(refused) != 1 || refused[0].Details["method"] != emailLoginProvider || refused[0].Details["reason"] != "code_mismatch" {
		t.Fatalf("sign-in refusals = %+v, want one email code_mismatch", refused)
	}

	if w := submitCode(s, cookie, code); w.Code != http.StatusFound {
		t.Fatalf("correct code: %d", w.Code)
	}
	ok := events.find(EventSignIn, audit.OutcomeSuccess)
	if len(ok) != 1 || ok[0].Details["method"] != emailLoginProvider {
		t.Fatalf("sign-ins = %+v, want one with method email", ok)
	}

	// A used code is refused as unusable.
	submitCode(s, cookie, code)
	var reasons []any
	for _, ev := range events.find(EventSignIn, audit.OutcomeFailure) {
		reasons = append(reasons, ev.Details["reason"])
	}
	if len(reasons) != 2 || reasons[1] != "code_unusable" {
		t.Fatalf("refusal reasons = %v, want code_mismatch then code_unusable", reasons)
	}

	// No event, as SystemAuth or OCSF records it, holds the code or the address.
	events.mu.Lock()
	all := append([]audit.Event(nil), events.events...)
	events.mu.Unlock()
	for _, ev := range all {
		text := ev.EventType + ev.Action + strings.Repeat(" ", 1)
		for k, v := range ev.Details {
			text += k + "=" + strings.ToLower(strings.TrimSpace(toString(v))) + " "
		}
		if strings.Contains(text, code) || strings.Contains(text, "jane.doe") {
			t.Errorf("event %s holds the code or the address: %v", ev.EventType, ev.Details)
		}
	}
	ocsf := events.ocsf(t)
	if strings.Contains(ocsf, code) || strings.Contains(ocsf, "jane.doe") {
		t.Errorf("an OCSF event holds the code or the address")
	}
	if !strings.Contains(ocsf, EventEmailCodeSent) {
		t.Errorf("the OCSF output has no %s event", EventEmailCodeSent)
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestEmailSignInExhaustedEvent(t *testing.T) {
	events := &eventCapture{}
	s, sender := newEmailLoginServer(t, &EmailLoginConfig{MaxAttempts: 3}, nil, nil, WithAuditEmitter(events))
	_, cookie := requestCode(t, s, "a@example.com")
	code := lastCode(t, sender)

	for i := 1; i <= 3; i++ {
		submitCode(s, cookie, wrongCode(code))
		want := 0
		if i == 3 {
			want = 1
		}
		if got := len(events.find(EventEmailCodeExhausted, audit.OutcomeFailure)); got != want {
			t.Fatalf("after %d wrong entries: %d exhausted events, want %d", i, got, want)
		}
	}
	// Entries past the limit do not repeat it.
	submitCode(s, cookie, wrongCode(code))
	if got := len(events.find(EventEmailCodeExhausted, "")); got != 1 {
		t.Fatalf("%d exhausted events after an entry past the limit, want 1", got)
	}
	if !strings.Contains(events.ocsf(t), EventEmailCodeExhausted) {
		t.Error("the OCSF output has no exhausted event")
	}
}

func TestEmailSignInSuppressedSendEvent(t *testing.T) {
	events := &eventCapture{}
	mail := &MailConfig{
		Provider: MailProviderSES, From: "Example <no-reply@example.com>",
		PerAddress: &RateLimitRule{Requests: 1, Period: Duration(time.Hour)},
	}
	s, _ := newEmailLoginServer(t, nil, mail, nil, WithAuditEmitter(events))
	requestCode(t, s, "a@example.com")
	requestCode(t, s, "a@example.com")
	sent := events.find(EventEmailCodeSent, "")
	if len(sent) != 2 || sent[0].Details["sent"] != true || sent[1].Details["sent"] != false {
		t.Fatalf("code sent events = %+v, want sent true then false", sent)
	}
}

func TestEmailSignInEntriesAreLimitedPerClient(t *testing.T) {
	s, sender := newEmailLoginServer(t, &EmailLoginConfig{MaxAttempts: 10}, nil, nil)
	_, cookie := requestCode(t, s, "a@example.com")
	wrong := wrongCode(lastCode(t, sender))
	limit := DefaultEmailCodeSubmitLimit.Rate
	for i := 1; i <= limit; i++ {
		if w := submitCode(s, cookie, wrong); w.Code == http.StatusTooManyRequests {
			t.Fatalf("entry %d of %d was limited", i, limit)
		}
	}
	if w := submitCode(s, cookie, wrong); w.Code != http.StatusTooManyRequests {
		t.Fatalf("entry %d: %d, want 429", limit+1, w.Code)
	}
}

func TestEmailSignInExhaustedOnceWhenEntriesRace(t *testing.T) {
	// Several wrong entries arriving together spend the tries between them;
	// only the one that spends the last try reports the code as exhausted.
	for round := range 10 {
		events := &eventCapture{}
		mail := &MailConfig{
			Provider: MailProviderSES, From: "Example <no-reply@example.com>",
			PerClient: &RateLimitRule{Requests: 1000, Period: Duration(time.Hour)},
		}
		s, sender := newEmailLoginServer(t, &EmailLoginConfig{MaxAttempts: 3}, mail, nil, WithAuditEmitter(events))
		_, cookie := requestCode(t, s, "a@example.com")
		wrong := wrongCode(lastCode(t, sender))

		const entries = 10
		var wg sync.WaitGroup
		codes := make(chan int, entries)
		for i := range entries {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w := postFrom(s, fmt.Sprintf("198.51.100.%d:4000", i+1), EmailCodePath,
					url.Values{"code": {wrong}, "csrf_token": {emailCodeCSRF(cookie.Value)}}, cookie)
				codes <- w.Code
			}()
		}
		wg.Wait()
		close(codes)
		// A wrong entry is answered 400, whether it had tries left or not; a
		// store failure would show as another status the event count misses.
		for code := range codes {
			if code != http.StatusBadRequest {
				t.Fatalf("round %d: an entry was answered %d, want 400", round, code)
			}
		}
		if got := len(events.find(EventEmailCodeExhausted, "")); got != 1 {
			t.Fatalf("round %d: %d exhausted events, want exactly 1", round, got)
		}
	}
}

func TestEmailSignInSuppressedRequestsAreRecorded(t *testing.T) {
	events := &eventCapture{}
	mail := &MailConfig{
		Provider: MailProviderSES, From: "Example <no-reply@example.com>",
		PerAddress: &RateLimitRule{Requests: 1, Period: Duration(time.Hour)},
	}
	s, sender := newEmailLoginServer(t, nil, mail, nil, WithAuditEmitter(events))
	_, cookie := requestCode(t, s, "a@example.com") // sent
	code := lastCode(t, sender)

	// A resend that cannot be sent changes nothing, and is recorded.
	postIssuerForm(s, EmailCodeResendPath, url.Values{"csrf_token": {emailCodeCSRF(cookie.Value)}}, cookie)
	// So is a repeated request for the address the browser already has pending.
	req := httptest.NewRequest(http.MethodPost, EmailLoginPath, strings.NewReader(url.Values{"email": {"a@example.com"}, "return_to": {emailTestReturn}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", testIssuer)
	req.AddCookie(cookie)
	s.ServeHTTP(httptest.NewRecorder(), req)

	var sent []any
	for _, ev := range events.find(EventEmailCodeSent, "") {
		sent = append(sent, ev.Details["sent"])
	}
	if len(sent) != 3 || sent[0] != true || sent[1] != false || sent[2] != false {
		t.Fatalf("code sent events = %v, want true, false, false", sent)
	}
	if w := submitCode(s, cookie, code); w.Code != http.StatusFound {
		t.Fatalf("the mailed code was lost: %d", w.Code)
	}
}
