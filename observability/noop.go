package observability

import (
	"context"
	"log/slog"

	"github.com/plexusone/omniobserve/observops"
)

// noopProvider is a no-op implementation of observops.Provider.
type noopProvider struct{}

func (n *noopProvider) Name() string             { return "noop" }
func (n *noopProvider) Meter() observops.Meter   { return &noopMeter{} }
func (n *noopProvider) Tracer() observops.Tracer { return &noopTracer{} }
func (n *noopProvider) Logger() observops.Logger { return &noopLogger{} }
func (n *noopProvider) SlogHandler(_ ...observops.SlogOption) slog.Handler {
	return observops.NoopSlogHandler()
}
func (n *noopProvider) Shutdown(_ context.Context) error   { return nil }
func (n *noopProvider) ForceFlush(_ context.Context) error { return nil }

// noopMeter is a no-op implementation of observops.Meter.
type noopMeter struct{}

func (n *noopMeter) Counter(_ string, _ ...observops.MetricOption) (observops.Counter, error) {
	return &noopCounter{}, nil
}

func (n *noopMeter) UpDownCounter(_ string, _ ...observops.MetricOption) (observops.UpDownCounter, error) {
	return &noopUpDownCounter{}, nil
}

func (n *noopMeter) Histogram(_ string, _ ...observops.MetricOption) (observops.Histogram, error) {
	return &noopHistogram{}, nil
}

func (n *noopMeter) Gauge(_ string, _ ...observops.MetricOption) (observops.Gauge, error) {
	return &noopGauge{}, nil
}

// noopCounter is a no-op implementation of observops.Counter.
type noopCounter struct{}

func (n *noopCounter) Add(_ context.Context, _ float64, _ ...observops.RecordOption) {}

// noopUpDownCounter is a no-op implementation of observops.UpDownCounter.
type noopUpDownCounter struct{}

func (n *noopUpDownCounter) Add(_ context.Context, _ float64, _ ...observops.RecordOption) {}

// noopHistogram is a no-op implementation of observops.Histogram.
type noopHistogram struct{}

func (n *noopHistogram) Record(_ context.Context, _ float64, _ ...observops.RecordOption) {}

// noopGauge is a no-op implementation of observops.Gauge.
type noopGauge struct{}

func (n *noopGauge) Record(_ context.Context, _ float64, _ ...observops.RecordOption) {}

// noopTracer is a no-op implementation of observops.Tracer.
type noopTracer struct{}

func (n *noopTracer) Start(ctx context.Context, _ string, _ ...observops.SpanOption) (context.Context, observops.Span) {
	return ctx, &noopSpan{}
}

func (n *noopTracer) SpanFromContext(_ context.Context) observops.Span {
	return &noopSpan{}
}

// noopSpan is a no-op implementation of observops.Span.
type noopSpan struct{}

func (n *noopSpan) End(_ ...observops.SpanEndOption)                {}
func (n *noopSpan) SetAttributes(_ ...observops.KeyValue)           {}
func (n *noopSpan) SetStatus(_ observops.StatusCode, _ string)      {}
func (n *noopSpan) RecordError(_ error, _ ...observops.EventOption) {}
func (n *noopSpan) AddEvent(_ string, _ ...observops.EventOption)   {}
func (n *noopSpan) SpanContext() observops.SpanContext              { return observops.SpanContext{} }
func (n *noopSpan) IsRecording() bool                               { return false }

// noopLogger is a no-op implementation of observops.Logger.
type noopLogger struct{}

func (n *noopLogger) Debug(_ context.Context, _ string, _ ...observops.LogAttribute) {}
func (n *noopLogger) Info(_ context.Context, _ string, _ ...observops.LogAttribute)  {}
func (n *noopLogger) Warn(_ context.Context, _ string, _ ...observops.LogAttribute)  {}
func (n *noopLogger) Error(_ context.Context, _ string, _ ...observops.LogAttribute) {}
