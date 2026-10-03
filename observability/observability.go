// Package observability provides vendor-agnostic observability for SystemForge applications.
// It wraps omniobserve/observops to provide metrics, traces, and logs with support for
// OTLP, Datadog, New Relic, and Dynatrace backends.
package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/plexusone/omniobserve/observops"

	"github.com/plexusone/systemforge/productgraph"
)

// Config holds observability configuration.
type Config struct {
	// Provider is the backend provider name: "otlp", "datadog", "newrelic", "dynatrace".
	// If empty, observability is disabled (noop provider).
	Provider string

	// ServiceName is the name of the service.
	ServiceName string

	// ServiceVersion is the version of the service.
	ServiceVersion string

	// Endpoint is the backend endpoint (e.g., "localhost:4317" for OTLP).
	Endpoint string

	// APIKey is the API key for authentication (required for some backends).
	APIKey string

	// Disabled explicitly disables observability.
	Disabled bool

	// Insecure disables TLS for the connection.
	Insecure bool

	// Debug enables debug logging for the provider.
	Debug bool
}

// ConfigFromEnv creates a Config from environment variables.
//
// Environment variables:
//   - OBSERVABILITY_PROVIDER: otlp, datadog, newrelic, dynatrace
//   - OBSERVABILITY_ENDPOINT: Backend endpoint
//   - OBSERVABILITY_API_KEY: API key for authentication
//   - OBSERVABILITY_SERVICE_NAME: Service name
//   - OBSERVABILITY_SERVICE_VERSION: Service version
//   - OBSERVABILITY_DISABLED: true/false
//   - OBSERVABILITY_INSECURE: true/false
//   - OBSERVABILITY_DEBUG: true/false
func ConfigFromEnv() Config {
	return Config{
		Provider:       os.Getenv("OBSERVABILITY_PROVIDER"),
		Endpoint:       os.Getenv("OBSERVABILITY_ENDPOINT"),
		APIKey:         os.Getenv("OBSERVABILITY_API_KEY"),
		ServiceName:    os.Getenv("OBSERVABILITY_SERVICE_NAME"),
		ServiceVersion: os.Getenv("OBSERVABILITY_SERVICE_VERSION"),
		Disabled:       os.Getenv("OBSERVABILITY_DISABLED") == "true",
		Insecure:       os.Getenv("OBSERVABILITY_INSECURE") == "true",
		Debug:          os.Getenv("OBSERVABILITY_DEBUG") == "true",
	}
}

// Observability wraps an observops.Provider with SystemForge-specific helpers.
type Observability struct {
	provider observops.Provider
	config   Config

	// ProductGraph client for event tracking
	productgraph *productgraph.Client

	// Pre-created metrics for SystemAuth
	authRequests     observops.Counter
	authLatency      observops.Histogram
	tokensIssued     observops.Counter
	tokenValidations observops.Counter
	sessionsActive   observops.Gauge

	// Pre-created metrics for CoreAPI / Rate Limiting
	rateLimitRequests observops.Counter
	rateLimitUsage    observops.Gauge

	// Pre-created metrics for Session middleware
	jwtValidations    observops.Counter
	jwtLatency        observops.Histogram
	apiKeyValidations observops.Counter
}

// New creates a new Observability instance from the given config.
// If the provider is empty or disabled, a noop provider is used.
func New(cfg Config) (*Observability, error) {
	if cfg.Disabled || cfg.Provider == "" {
		return newNoop(), nil
	}

	opts := buildClientOptions(cfg)
	provider, err := observops.Open(cfg.Provider, opts...)
	if err != nil {
		return nil, fmt.Errorf("observability: failed to open provider %q: %w", cfg.Provider, err)
	}

	o := &Observability{
		provider: provider,
		config:   cfg,
	}

	if err := o.initMetrics(); err != nil {
		_ = provider.Shutdown(context.Background())
		return nil, fmt.Errorf("observability: failed to initialize metrics: %w", err)
	}

	return o, nil
}

// MustNew is like New but panics on error.
func MustNew(cfg Config) *Observability {
	o, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return o
}

// newNoop creates a noop observability instance.
func newNoop() *Observability {
	return &Observability{
		provider: &noopProvider{},
		config:   Config{Disabled: true},
	}
}

// buildClientOptions builds observops.ClientOption from Config.
func buildClientOptions(cfg Config) []observops.ClientOption {
	var opts []observops.ClientOption

	if cfg.ServiceName != "" {
		opts = append(opts, observops.WithServiceName(cfg.ServiceName))
	}
	if cfg.ServiceVersion != "" {
		opts = append(opts, observops.WithServiceVersion(cfg.ServiceVersion))
	}
	if cfg.Endpoint != "" {
		opts = append(opts, observops.WithEndpoint(cfg.Endpoint))
	}
	if cfg.APIKey != "" {
		opts = append(opts, observops.WithAPIKey(cfg.APIKey))
	}
	if cfg.Insecure {
		opts = append(opts, observops.WithInsecure())
	}
	if cfg.Debug {
		opts = append(opts, observops.WithDebug())
	}

	return opts
}

// initMetrics initializes pre-defined metrics.
func (o *Observability) initMetrics() error {
	var err error
	meter := o.provider.Meter()

	// SystemAuth metrics
	o.authRequests, err = meter.Counter(MetricAuthRequests,
		observops.WithDescription("Total authentication/authorization requests"),
		observops.WithUnit("{request}"),
	)
	if err != nil {
		return err
	}

	o.authLatency, err = meter.Histogram(MetricAuthLatency,
		observops.WithDescription("Authentication/authorization request latency"),
		observops.WithUnit("ms"),
	)
	if err != nil {
		return err
	}

	o.tokensIssued, err = meter.Counter(MetricTokensIssued,
		observops.WithDescription("Total tokens issued"),
		observops.WithUnit("{token}"),
	)
	if err != nil {
		return err
	}

	o.tokenValidations, err = meter.Counter(MetricTokenValidations,
		observops.WithDescription("Total token validations"),
		observops.WithUnit("{validation}"),
	)
	if err != nil {
		return err
	}

	o.sessionsActive, err = meter.Gauge(MetricSessionsActive,
		observops.WithDescription("Currently active sessions"),
		observops.WithUnit("{session}"),
	)
	if err != nil {
		return err
	}

	// Rate limiting metrics
	o.rateLimitRequests, err = meter.Counter(MetricRateLimitRequests,
		observops.WithDescription("Total rate limit checks"),
		observops.WithUnit("{request}"),
	)
	if err != nil {
		return err
	}

	o.rateLimitUsage, err = meter.Gauge(MetricRateLimitUsage,
		observops.WithDescription("Current rate limit usage ratio"),
		observops.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	// Session middleware metrics
	o.jwtValidations, err = meter.Counter(MetricJWTValidations,
		observops.WithDescription("Total JWT validations"),
		observops.WithUnit("{validation}"),
	)
	if err != nil {
		return err
	}

	o.jwtLatency, err = meter.Histogram(MetricJWTLatency,
		observops.WithDescription("JWT validation latency"),
		observops.WithUnit("ms"),
	)
	if err != nil {
		return err
	}

	o.apiKeyValidations, err = meter.Counter(MetricAPIKeyValidations,
		observops.WithDescription("Total API key validations"),
		observops.WithUnit("{validation}"),
	)
	if err != nil {
		return err
	}

	return nil
}

// Provider returns the underlying observops.Provider.
func (o *Observability) Provider() observops.Provider {
	return o.provider
}

// Meter returns the metrics meter.
func (o *Observability) Meter() observops.Meter {
	return o.provider.Meter()
}

// Tracer returns the tracer for creating spans.
func (o *Observability) Tracer() observops.Tracer {
	return o.provider.Tracer()
}

// Logger returns the structured logger.
func (o *Observability) Logger() observops.Logger {
	return o.provider.Logger()
}

// SlogHandler returns an slog.Handler that integrates with this provider.
// Options can be used to configure local output and filtering.
func (o *Observability) SlogHandler(opts ...observops.SlogOption) slog.Handler {
	return o.provider.SlogHandler(opts...)
}

// Shutdown gracefully shuts down the provider and ProductGraph client.
func (o *Observability) Shutdown(ctx context.Context) error {
	var errs []error

	// Shutdown ProductGraph first (flush events)
	if o.productgraph != nil {
		if err := o.productgraph.Close(); err != nil {
			errs = append(errs, fmt.Errorf("productgraph: %w", err))
		}
	}

	// Shutdown observability provider
	if err := o.provider.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("provider: %w", err))
	}

	return errors.Join(errs...)
}

// ForceFlush forces any buffered telemetry to be exported.
func (o *Observability) ForceFlush(ctx context.Context) error {
	return o.provider.ForceFlush(ctx)
}

// IsEnabled returns true if observability is enabled.
func (o *Observability) IsEnabled() bool {
	return !o.config.Disabled && o.config.Provider != ""
}

// Config returns the observability configuration.
func (o *Observability) Config() Config {
	return o.config
}

// RecordAuthRequest records an authentication/authorization request metric.
func (o *Observability) RecordAuthRequest(ctx context.Context, grantType, clientID, status string) {
	o.authRequests.Add(ctx, 1, observops.WithAttributes(
		observops.Attribute("grant_type", grantType),
		observops.Attribute("client_id", clientID),
		observops.Attribute("status", status),
	))
}

// RecordAuthLatency records authentication latency in milliseconds.
func (o *Observability) RecordAuthLatency(ctx context.Context, grantType, endpoint string, latencyMs float64) {
	o.authLatency.Record(ctx, latencyMs, observops.WithAttributes(
		observops.Attribute("grant_type", grantType),
		observops.Attribute("endpoint", endpoint),
	))
}

// RecordTokenIssued records a token issuance.
func (o *Observability) RecordTokenIssued(ctx context.Context, grantType, clientID string) {
	o.tokensIssued.Add(ctx, 1, observops.WithAttributes(
		observops.Attribute("grant_type", grantType),
		observops.Attribute("client_id", clientID),
	))
}

// RecordTokenValidation records a token validation result.
func (o *Observability) RecordTokenValidation(ctx context.Context, result string) {
	o.tokenValidations.Add(ctx, 1, observops.WithAttributes(
		observops.Attribute("result", result),
	))
}

// RecordSessionsActive records the current number of active sessions.
func (o *Observability) RecordSessionsActive(ctx context.Context, count int) {
	o.sessionsActive.Record(ctx, float64(count))
}

// RecordRateLimitRequest records a rate limit check.
func (o *Observability) RecordRateLimitRequest(ctx context.Context, policyID, clientID string, allowed bool) {
	o.rateLimitRequests.Add(ctx, 1, observops.WithAttributes(
		observops.Attribute("policy_id", policyID),
		observops.Attribute("client_id", clientID),
		observops.Attribute("allowed", strconv.FormatBool(allowed)),
	))
}

// RecordRateLimitUsage records the current rate limit usage ratio (0.0 to 1.0).
func (o *Observability) RecordRateLimitUsage(ctx context.Context, policyID, clientID, window string, usage float64) {
	o.rateLimitUsage.Record(ctx, usage, observops.WithAttributes(
		observops.Attribute("policy_id", policyID),
		observops.Attribute("client_id", clientID),
		observops.Attribute("window", window),
	))
}

// RecordJWTValidation records a JWT validation result.
func (o *Observability) RecordJWTValidation(ctx context.Context, result string) {
	o.jwtValidations.Add(ctx, 1, observops.WithAttributes(
		observops.Attribute("result", result),
	))
}

// RecordJWTLatency records JWT validation latency in milliseconds.
func (o *Observability) RecordJWTLatency(ctx context.Context, latencyMs float64) {
	o.jwtLatency.Record(ctx, latencyMs)
}

// RecordAPIKeyValidation records an API key validation result.
func (o *Observability) RecordAPIKeyValidation(ctx context.Context, result string) {
	o.apiKeyValidations.Add(ctx, 1, observops.WithAttributes(
		observops.Attribute("result", result),
	))
}

// StartSpan creates a new span with the given name.
func (o *Observability) StartSpan(ctx context.Context, name string, opts ...observops.SpanOption) (context.Context, observops.Span) {
	return o.provider.Tracer().Start(ctx, name, opts...)
}

// SpanFromContext retrieves the current span from context.
func (o *Observability) SpanFromContext(ctx context.Context) observops.Span {
	return o.provider.Tracer().SpanFromContext(ctx)
}

// SetProductGraph configures ProductGraph integration.
// This should be called after New() if you want to enable ProductGraph.
// Returns an error if the configuration is invalid.
func (o *Observability) SetProductGraph(cfg productgraph.Config) error {
	if !cfg.IsEnabled() {
		return nil
	}

	client, err := productgraph.New(cfg)
	if err != nil {
		return fmt.Errorf("observability: failed to create ProductGraph client: %w", err)
	}

	// Set logger to match observability
	if o.IsEnabled() {
		client.SetLogger(slog.New(o.SlogHandler()))
	}

	o.productgraph = client
	return nil
}

// SetProductGraphFromEnv configures ProductGraph from environment variables.
// Environment variables:
//   - PRODUCTGRAPH_PROJECT_ID: Project identifier
//   - PRODUCTGRAPH_ENDPOINT: API endpoint
//   - PRODUCTGRAPH_API_KEY: API key (optional)
//   - PRODUCTGRAPH_BATCH_SIZE: Events per batch (default: 50)
//   - PRODUCTGRAPH_BATCH_INTERVAL: Flush interval in seconds (default: 5)
//   - PRODUCTGRAPH_DEBUG: Enable debug logging
func (o *Observability) SetProductGraphFromEnv() error {
	cfg := productgraph.ConfigFromEnv()
	return o.SetProductGraph(cfg)
}
