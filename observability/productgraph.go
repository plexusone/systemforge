package observability

import (
	"context"
	"net/http"
	"time"

	"github.com/plexusone/systemforge/productgraph"
)

// ProductGraphConfig holds ProductGraph-specific configuration.
// Use productgraph.ConfigFromEnv() to load from environment variables.
type ProductGraphConfig = productgraph.Config

// ProductGraphClient returns the ProductGraph client if configured.
// Returns nil if ProductGraph is not enabled.
func (o *Observability) ProductGraphClient() *productgraph.Client {
	return o.productgraph
}

// ProductGraphEnabled returns true if ProductGraph integration is enabled.
func (o *Observability) ProductGraphEnabled() bool {
	return o.productgraph != nil && o.productgraph.IsEnabled()
}

// TrackProductGraphEvent sends an event to ProductGraph.
// No-op if ProductGraph is not configured.
func (o *Observability) TrackProductGraphEvent(ctx context.Context, event productgraph.Event) {
	if o.productgraph == nil {
		return
	}
	_ = o.productgraph.Track(ctx, event)
}

// TrackAPICall tracks an API call to ProductGraph.
// No-op if ProductGraph is not configured.
func (o *Observability) TrackAPICall(ctx context.Context, method, path string, statusCode int, duration time.Duration) {
	if o.productgraph == nil {
		return
	}
	_ = o.productgraph.TrackAPICall(ctx, method, path, statusCode, duration)
}

// TrackError tracks an error to ProductGraph.
// No-op if ProductGraph is not configured.
func (o *Observability) TrackError(ctx context.Context, errType, message string) {
	if o.productgraph == nil {
		return
	}
	_ = o.productgraph.TrackError(ctx, errType, message)
}

// TrackJourneyStep tracks a journey step to ProductGraph.
// No-op if ProductGraph is not configured.
func (o *Observability) TrackJourneyStep(ctx context.Context, journeyID, stepID, stepName string) {
	if o.productgraph == nil {
		return
	}
	_ = o.productgraph.TrackJourneyStep(ctx, journeyID, stepID, stepName)
}

// ProductGraphCorrelationMiddleware returns middleware that extracts
// correlation headers (X-Session-ID, X-Request-ID) from requests. It does not
// read a user ID from the request; set it from the authenticated session
// with productgraph.WithUserID. This should be used early in the middleware
// chain.
func ProductGraphCorrelationMiddleware() func(http.Handler) http.Handler {
	return productgraph.CorrelationMiddleware
}

// ProductGraphRequestTrackerMiddleware returns middleware that tracks
// HTTP requests to ProductGraph. Requires ProductGraph to be configured.
func (o *Observability) ProductGraphRequestTrackerMiddleware() func(http.Handler) http.Handler {
	return productgraph.RequestTrackerMiddleware(o.productgraph)
}

// ProductGraphMiddleware returns a combined middleware that handles both
// correlation extraction and request tracking. This is the recommended
// middleware for most use cases.
func (o *Observability) ProductGraphMiddleware() func(http.Handler) http.Handler {
	return productgraph.ChainMiddleware(o.productgraph)
}
