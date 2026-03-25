package telemetry

import (
	logNoop "go.opentelemetry.io/otel/log/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	traceNoop "go.opentelemetry.io/otel/trace/noop"
)

// NewProviderForTest creates a Provider wired to the given ManualReader so
// that tests can call reader.Collect() to inspect emitted metrics. The
// provider reports Enabled()=true and has a fully initialised metricsSet.
func NewProviderForTest(reader *sdkmetric.ManualReader) (*Provider, error) {
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m := mp.Meter("defenseclaw-test")

	ms, err := newMetricsSet(m)
	if err != nil {
		return nil, err
	}

	return &Provider{
		enabled:       true,
		meterProvider: mp,
		meter:         m,
		metrics:       ms,
		tracer:        traceNoop.NewTracerProvider().Tracer("test"),
		logger:        logNoop.NewLoggerProvider().Logger("test"),
	}, nil
}
