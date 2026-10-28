package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexusone/payforge"
	payforgestripe "github.com/plexusone/payforge/stripe"
	"github.com/plexusone/systemspec-pricingpackaging/pricingspec"
)

const testSecret = "whsec_test_fake" //nolint:gosec // G101: a fake secret for a test

// sign returns a Stripe-Signature header for payload.
func sign(payload string, at time.Time) string {
	mac := hmac.New(sha256.New, []byte(testSecret))
	if _, err := fmt.Fprintf(mac, "%d.%s", at.Unix(), payload); err != nil {
		panic(err) // a hash never fails to write
	}
	return fmt.Sprintf("t=%d,v1=%s", at.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

func loadSpec(t *testing.T) *pricingspec.Spec {
	t.Helper()
	f, err := os.Open("testdata/pricing.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	spec, err := pricingspec.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func subscriptionEvent(app string) string {
	const subject = "org-1"
	return `{"id":"evt_1","object":"event","created":1790000000,"livemode":false,
"type":"customer.subscription.updated","data":{"object":{"id":"sub_1","status":"active","customer":"cus_1",
"metadata":{"payforge_app":"` + app + `","payforge_subject":"` + subject + `"},
"items":{"data":[{"price":{"id":"price_a","lookup_key":"` + app + `/pro/month"}}]}}}}`
}

func checkoutEvent(id, app, subject string) string {
	return `{"id":"` + id + `","object":"event","created":1790000000,"livemode":false,
"type":"checkout.session.completed","data":{"object":{"id":"cs_1","object":"checkout.session","mode":"payment",
"payment_status":"paid","customer":"cus_1","payment_intent":"pi_1","amount_total":2500,"currency":"usd",
"metadata":{"payforge_app":"` + app + `","payforge_subject":"` + subject + `","payforge_product":"listing"}}}}`
}

// flakySink fails its first n applies.
type flakySink struct {
	*payforge.MemorySink
	mu    sync.Mutex
	fails int
}

func (s *flakySink) Apply(ctx context.Context, e payforge.Entitlement) error {
	s.mu.Lock()
	if s.fails > 0 {
		s.fails--
		s.mu.Unlock()
		return errors.New("database is down: secret detail")
	}
	s.mu.Unlock()
	return s.MemorySink.Apply(ctx, e)
}

type recordingCompleter struct {
	mu   sync.Mutex
	seen []string
}

func (c *recordingCompleter) CompleteCheckout(_ context.Context, ev payforge.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = append(c.seen, ev.Checkout.SessionID)
	return nil
}

type webhookRig struct {
	h         http.Handler
	sink      *flakySink
	completer *recordingCompleter
	logs      *bytes.Buffer
}

func newWebhookRig(t *testing.T) *webhookRig {
	t.Helper()
	store := NewStore(openDB(t))
	rig := &webhookRig{
		sink:      &flakySink{MemorySink: payforge.NewMemorySink()},
		completer: &recordingCompleter{},
		logs:      &bytes.Buffer{},
	}
	life := &payforge.Lifecycle{Spec: loadSpec(t), Store: store, Sink: rig.sink, Locker: &payforge.MemoryLocker{}}
	h, err := NewWebhookHandler(WebhookConfig{
		Reader:    payforgestripe.Webhook{Mode: payforgestripe.ModeTest, Secrets: []string{testSecret}, MaxBytes: 4096},
		Lifecycle: life,
		Store:     store,
		Checkouts: rig.completer,
		Logger:    slog.New(slog.NewTextHandler(rig.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	rig.h = h
	return rig
}

func (r *webhookRig) post(body, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/billing/webhook", strings.NewReader(body))
	req.Header.Set("Stripe-Signature", sig)
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

func expect(t *testing.T, w *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if w.Code != status || w.Body.String() != body+"\n" {
		t.Fatalf("got %d %q, want %d %q", w.Code, w.Body.String(), status, body)
	}
}

func TestWebhookAppliesOnce(t *testing.T) {
	r := newWebhookRig(t)
	body := subscriptionEvent("demoapp")
	expect(t, r.post(body, sign(body, time.Now())), http.StatusOK, "ok")
	expect(t, r.post(body, sign(body, time.Now())), http.StatusOK, "ok")
	if n := len(r.sink.History()); n != 1 {
		t.Fatalf("applied %d times, want 1", n)
	}
	if e, ok := r.sink.Get("org-1"); !ok || e.Plan != "pro" || !e.Granted {
		t.Fatalf("entitlement = %+v, %v", e, ok)
	}
}

func TestWebhookRejectsWithoutDetail(t *testing.T) {
	r := newWebhookRig(t)
	body := subscriptionEvent("demoapp")

	expect(t, r.post(body, sign(body+" ", time.Now())), http.StatusBadRequest, "invalid signature")
	expect(t, r.post(body, ""), http.StatusBadRequest, "invalid signature")
	expect(t, r.post(body, sign(body, time.Now().Add(-time.Hour))), http.StatusBadRequest, "invalid signature")

	big := strings.Repeat(" ", 5000) + body
	expect(t, r.post(big, sign(big, time.Now())), http.StatusRequestEntityTooLarge, "payload too large")

	req := httptest.NewRequest(http.MethodGet, "/billing/webhook", nil)
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	expect(t, w, http.StatusMethodNotAllowed, "method not allowed")
	if len(r.sink.History()) != 0 {
		t.Fatal("a rejected request was applied")
	}
}

func TestWebhookRetriesOnlyFailures(t *testing.T) {
	r := newWebhookRig(t)
	r.sink.fails = 1
	body := subscriptionEvent("demoapp")

	w := r.post(body, sign(body, time.Now()))
	expect(t, w, http.StatusInternalServerError, "error")
	if strings.Contains(w.Body.String(), "secret detail") {
		t.Fatal("error detail in the response")
	}
	if !strings.Contains(r.logs.String(), "secret detail") {
		t.Fatal("the cause was not logged")
	}
	// The provider redelivers, and this time it applies.
	expect(t, r.post(body, sign(body, time.Now())), http.StatusOK, "ok")
	if n := len(r.sink.History()); n != 1 {
		t.Fatalf("applied %d times, want 1", n)
	}
}

func TestWebhookAcknowledgesForeignEvents(t *testing.T) {
	r := newWebhookRig(t)
	sub := subscriptionEvent("otherapp")
	expect(t, r.post(sub, sign(sub, time.Now())), http.StatusOK, "ok")
	co := checkoutEvent("evt_2", "otherapp", "org-1")
	expect(t, r.post(co, sign(co, time.Now())), http.StatusOK, "ok")
	live := strings.Replace(subscriptionEvent("demoapp"), `"livemode":false`, `"livemode":true`, 1)
	expect(t, r.post(live, sign(live, time.Now())), http.StatusOK, "ok")
	unknown := `{"id":"evt_3","object":"event","type":"payout.paid","data":{"object":{"id":"po_1"}}}`
	expect(t, r.post(unknown, sign(unknown, time.Now())), http.StatusOK, "ok")
	if len(r.sink.History()) != 0 || len(r.completer.seen) != 0 {
		t.Fatalf("a foreign event was applied: %d, %v", len(r.sink.History()), r.completer.seen)
	}
}

func TestWebhookCompletesCheckoutOnce(t *testing.T) {
	r := newWebhookRig(t)
	co := checkoutEvent("evt_1", "demoapp", "org-1")
	expect(t, r.post(co, sign(co, time.Now())), http.StatusOK, "ok")
	expect(t, r.post(co, sign(co, time.Now())), http.StatusOK, "ok")
	if len(r.completer.seen) != 1 || r.completer.seen[0] != "cs_1" {
		t.Fatalf("completed %v, want [cs_1]", r.completer.seen)
	}
}

type failingReader struct{}

func (failingReader) Read(*http.Request) (payforge.Event, error) {
	return payforge.Event{}, errors.New("no webhook secret configured")
}

func TestWebhookReadFailureIs500(t *testing.T) {
	store := NewStore(openDB(t))
	h, err := NewWebhookHandler(WebhookConfig{
		Reader:    failingReader{},
		Lifecycle: &payforge.Lifecycle{Spec: loadSpec(t), Store: store, Sink: payforge.NewMemorySink()},
		Store:     store,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")))
	expect(t, w, http.StatusInternalServerError, "error")
}

func TestNewWebhookHandlerRequiresParts(t *testing.T) {
	if _, err := NewWebhookHandler(WebhookConfig{}); err == nil {
		t.Fatal("an empty config was accepted")
	}
	store := NewStore(openDB(t))
	_, err := NewWebhookHandler(WebhookConfig{
		Reader:    failingReader{},
		Lifecycle: &payforge.Lifecycle{Spec: loadSpec(t)},
		Store:     store,
		Checkouts: &recordingCompleter{},
	})
	if err == nil || !strings.Contains(err.Error(), "locker") {
		t.Fatalf("a config without a locker: %v", err)
	}
}
