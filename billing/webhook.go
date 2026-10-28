package billing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/plexusone/payforge"
)

// WebhookReader verifies a webhook request and reduces it to an event.
// payforge's provider adapters implement it (payforge/stripe.Webhook, whose
// Mode must be set); keep their body limit.
type WebhookReader interface {
	Read(r *http.Request) (payforge.Event, error)
}

// EventHandler handles a verified event. *payforge.Lifecycle implements it.
type EventHandler interface {
	Handle(ctx context.Context, ev payforge.Event) (payforge.Result, error)
}

// CheckoutCompleter records a one-time checkout that was paid, or whose
// delayed payment failed, which payforge's lifecycle leaves to the host.
// [Sink] implements it. It must be safe to call more than once for the
// same checkout.
type CheckoutCompleter interface {
	CompleteCheckout(ctx context.Context, ev payforge.Event) error
}

// WebhookConfig configures the webhook endpoint. Reader, Lifecycle and
// Store are required, and a Locker when Checkouts is set.
type WebhookConfig struct {
	Reader    WebhookReader
	Lifecycle EventHandler
	// Store is the lifecycle's store. It finds the organization of a
	// checkout that names only a customer, and records completed checkouts
	// as processed.
	Store payforge.Store
	// Locker is held per organization, under payforge.LockKey, around a
	// completed checkout, as the lifecycle holds it around its own events.
	// Use the lifecycle's Locker; it defaults to that of a
	// *payforge.Lifecycle.
	Locker payforge.Locker
	// Checkouts, when set, receives one-time checkouts for marketplace
	// listings. Without it they are acknowledged and not recorded.
	Checkouts CheckoutCompleter
	// App is the pricing spec's app. A checkout for another app is
	// acknowledged and not passed to Checkouts. It defaults to the spec of
	// a *payforge.Lifecycle.
	App string
	// Logger receives one line per event. It defaults to slog.Default().
	Logger *slog.Logger
}

// NewWebhookHandler returns the endpoint the payment provider posts events
// to. It answers:
//
//   - 405 to anything but POST;
//   - 400 when the signature does not verify, and 413 when the body is over
//     the reader's limit: a retry cannot fix either;
//   - 500 when the event could not be read or handled, including a lock
//     that could not be taken, so the provider redelivers it;
//   - 200 otherwise, including an event that was a duplicate, was ignored
//     (an event of the other mode among them), or was skipped because it
//     belongs to another app or account.
//
// A response body is a fixed word or two and never carries error detail;
// the cause is logged.
//
// Serve it from an http.Server with ReadHeaderTimeout and ReadTimeout set:
// the body is read before the signature is checked.
func NewWebhookHandler(cfg WebhookConfig) (http.Handler, error) {
	if l, ok := cfg.Lifecycle.(*payforge.Lifecycle); ok && l != nil {
		if cfg.App == "" && l.Spec != nil {
			cfg.App = l.Spec.App
		}
		if cfg.Locker == nil {
			cfg.Locker = l.Locker
		}
	}
	switch {
	case cfg.Reader == nil:
		return nil, errors.New("billing: webhook needs a reader")
	case cfg.Lifecycle == nil:
		return nil, errors.New("billing: webhook needs a lifecycle")
	case cfg.Store == nil:
		return nil, errors.New("billing: webhook needs a store")
	case cfg.Checkouts != nil && cfg.Locker == nil:
		return nil, errors.New("billing: webhook needs a locker to complete checkouts")
	case cfg.Checkouts != nil && cfg.App == "":
		return nil, errors.New("billing: webhook needs the app to complete checkouts")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &webhookHandler{cfg: cfg}, nil
}

type webhookHandler struct {
	cfg WebhookConfig
}

func (h *webhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := h.cfg.Logger
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeText(ctx, log, w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ev, err := h.cfg.Reader.Read(r)
	switch {
	case errors.Is(err, payforge.ErrSignatureInvalid):
		log.InfoContext(ctx, "billing webhook: signature does not verify", "error", err)
		writeText(ctx, log, w, http.StatusBadRequest, "invalid signature")
		return
	case errors.Is(err, payforge.ErrPayloadTooLarge):
		log.WarnContext(ctx, "billing webhook: payload too large")
		writeText(ctx, log, w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	case err != nil:
		// Signed but unreadable, or no secret configured: ours to fix, so
		// answer 5xx and let the provider redeliver once it is.
		log.ErrorContext(ctx, "billing webhook: cannot read event", "error", err)
		writeText(ctx, log, w, http.StatusInternalServerError, "error")
		return
	}

	res, err := h.handle(ctx, ev)
	if err != nil {
		log.ErrorContext(ctx, "billing webhook: cannot handle event", "event", ev.ID, "type", ev.Type, "error", err)
		writeText(ctx, log, w, http.StatusInternalServerError, "error")
		return
	}
	attrs := []any{"event", ev.ID, "type", ev.Type, "outcome", res.Outcome}
	switch res.Outcome {
	case payforge.OutcomeSkipped:
		log.WarnContext(ctx, "billing webhook: event skipped", append(attrs, "reason", res.Reason)...)
	case payforge.OutcomeApplied:
		log.InfoContext(ctx, "billing webhook: event applied", attrs...)
	default:
		log.DebugContext(ctx, "billing webhook: event acknowledged", append(attrs, "reason", res.Reason)...)
	}
	writeText(ctx, log, w, http.StatusOK, "ok")
}

// handle passes the event to the lifecycle, which holds its own lock, and a
// one-time checkout, which the lifecycle ignores, to Checkouts.
func (h *webhookHandler) handle(ctx context.Context, ev payforge.Event) (payforge.Result, error) {
	res, err := h.cfg.Lifecycle.Handle(ctx, ev)
	if err != nil {
		return payforge.Result{}, err
	}
	isCheckout := ev.Kind == payforge.EventCheckoutCompleted || ev.Kind == payforge.EventCheckoutFailed
	if !isCheckout || res.Outcome != payforge.OutcomeIgnored || h.cfg.Checkouts == nil {
		return res, nil
	}
	return h.completeCheckout(ctx, ev)
}

func (h *webhookHandler) completeCheckout(ctx context.Context, ev payforge.Event) (payforge.Result, error) {
	switch {
	case ev.ID == "":
		return payforge.Result{Outcome: payforge.OutcomeSkipped, Reason: "the event has no ID"}, nil
	case ev.Checkout == nil:
		return payforge.Result{Outcome: payforge.OutcomeSkipped, Reason: "the event carries no checkout"}, nil
	case ev.Account != "":
		return payforge.Result{Outcome: payforge.OutcomeSkipped, Reason: "event is from a connected account, not the platform"}, nil
	case ev.App != "" && ev.App != h.cfg.App:
		return payforge.Result{Outcome: payforge.OutcomeSkipped, Reason: "event is for app " + ev.App}, nil
	case ev.Checkout.Mode != "payment":
		return payforge.Result{Outcome: payforge.OutcomeIgnored, Reason: "applied from the subscription events"}, nil
	case ev.Kind == payforge.EventCheckoutCompleted && !ev.Checkout.Paid:
		// A delayed payment method completes later with its own event.
		return payforge.Result{Outcome: payforge.OutcomeIgnored, Reason: "the checkout is not paid yet"}, nil
	}
	subject, err := h.subject(ctx, ev)
	if err != nil {
		return payforge.Result{}, err
	}
	if subject == "" {
		// The order recorded at checkout names the organization, but the
		// lock is taken before it is read; an unknown buyer is not ours.
		return payforge.Result{Outcome: payforge.OutcomeSkipped, Reason: "no organization is known for the checkout"}, nil
	}
	unlock, err := h.cfg.Locker.Lock(ctx, payforge.LockKey(h.cfg.App, subject))
	if err != nil {
		return payforge.Result{}, fmt.Errorf("lock organization: %w", err)
	}
	defer unlock()

	seen, err := h.cfg.Store.Seen(ctx, ev.ID)
	if err != nil {
		return payforge.Result{}, fmt.Errorf("check event: %w", err)
	}
	if seen {
		return payforge.Result{Outcome: payforge.OutcomeDuplicate}, nil
	}
	if err := h.cfg.Checkouts.CompleteCheckout(ctx, ev); err != nil {
		return payforge.Result{}, fmt.Errorf("complete checkout: %w", err)
	}
	if err := h.cfg.Store.MarkSeen(ctx, ev.ID); err != nil {
		return payforge.Result{}, fmt.Errorf("record event: %w", err)
	}
	return payforge.Result{Outcome: payforge.OutcomeApplied}, nil
}

// subject is the organization a checkout is for: the one its metadata
// names, else the one its customer is linked to. Empty means unknown.
func (h *webhookHandler) subject(ctx context.Context, ev payforge.Event) (string, error) {
	if ev.Subject != "" || ev.CustomerID == "" {
		return ev.Subject, nil
	}
	s, err := h.cfg.Store.SubjectForCustomer(ctx, ev.CustomerID)
	if errors.Is(err, payforge.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("find organization: %w", err)
	}
	return s, nil
}

// writeText writes a short plain-text response. A failed write means the
// client has gone; it is logged, as nothing else can be done with it.
func writeText(ctx context.Context, log *slog.Logger, w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body + "\n")); err != nil {
		log.DebugContext(ctx, "billing: writing response", "error", err)
	}
}
