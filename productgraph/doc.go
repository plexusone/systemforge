// Package productgraph provides a client for sending telemetry events to ProductGraph
// and middleware for frontend-backend correlation.
//
// # Overview
//
// ProductGraph is a product analytics platform that collects and analyzes user behavior
// events from both frontend and backend systems. This package enables Go services to:
//
//   - Send events to ProductGraph with batching and async dispatch
//   - Correlate backend requests with frontend sessions
//   - Track API calls, errors, and journey steps
//
// # Quick Start
//
//	// Create client
//	client, err := productgraph.New(productgraph.Config{
//	    ProjectID: "my-project",
//	    Endpoint:  "https://api.productgraph.io/v1/events",
//	    APIKey:    os.Getenv("PRODUCTGRAPH_API_KEY"),
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Use middleware for automatic tracking
//	r := chi.NewRouter()
//	r.Use(productgraph.ChainMiddleware(client))
//
//	// Or track events manually
//	client.TrackAPICall(ctx, "POST", "/checkout", 200, 150*time.Millisecond)
//	client.TrackJourneyStep(ctx, "checkout_flow", "payment", "Enter Payment")
//	client.TrackError(ctx, "ValidationError", "invalid card number")
//
// # Correlation
//
// The [CorrelationMiddleware] extracts frontend correlation headers and injects
// them into the request context:
//
//   - X-Session-ID: Frontend session identifier
//   - X-Request-ID: Per-request identifier (generated if not provided)
//
// The user ID is never taken from a request header. Set it from the
// authenticated session or token with [WithUserID], in middleware that runs
// after authentication and before the request tracker.
//
// Use [SessionIDFromContext], [RequestIDFromContext], and [UserIDFromContext]
// to retrieve these values in your handlers.
//
// [RequestTrackerMiddleware] records the matched route pattern
// (http.ServeMux's Request.Pattern or chi's route pattern, or "unmatched"),
// never the raw request path, which can carry tokens.
//
// # Event Types
//
// ProductGraph supports various event types following OTel semantic conventions:
//
//   - page.view, page.leave: Page navigation
//   - ui.click, ui.input, ui.scroll, ui.submit: User interactions
//   - state.change: Application state changes
//   - api.request, api.response: API calls
//   - journey.step: User journey progression
//   - error: Application errors
//   - performance: Performance metrics
//
// # Configuration
//
// Use [ConfigFromEnv] to load configuration from environment variables:
//
//   - PRODUCTGRAPH_PROJECT_ID: Project identifier
//   - PRODUCTGRAPH_ENDPOINT: API endpoint
//   - PRODUCTGRAPH_API_KEY: Authentication key
//   - PRODUCTGRAPH_BATCH_SIZE: Events per batch (default: 50)
//   - PRODUCTGRAPH_BATCH_INTERVAL: Flush interval in seconds (default: 5)
//   - PRODUCTGRAPH_DEBUG: Enable debug logging
package productgraph
