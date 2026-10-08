// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled        bool
	ServiceName    string
	ServiceVersion string
	OTLPEndpoint   string // e.g., "localhost:4318"
	InsecureMode   bool
	PrometheusPort string // Port for Prometheus scraping endpoint
}

// MetricsProvider wraps OpenTelemetry metrics provider
type MetricsProvider struct {
	provider           *sdkmetric.MeterProvider
	meter              metric.Meter
	prometheusExporter *prometheus.Exporter

	// HTTP metrics
	httpRequestCounter  metric.Int64Counter
	httpRequestDuration metric.Float64Histogram

	// gRPC metrics
	grpcRequestCounter  metric.Int64Counter
	grpcRequestDuration metric.Float64Histogram

	// Custom business metrics
	sessionsCreatedCounter metric.Int64Counter
	tokensMintedCounter    metric.Int64Counter
	keysRotatedCounter     metric.Int64Counter
	activeKeysGauge        metric.Int64ObservableGauge
	m2mClampedTTLHistogram metric.Float64Histogram
}

// NewMetricsProvider creates a new OpenTelemetry metrics provider with OTLP and Prometheus exporters
func NewMetricsProvider(config MetricsConfig) (*MetricsProvider, error) {
	if !config.Enabled {
		// Return no-op provider with initialized metrics instruments
		mp := &MetricsProvider{
			provider: nil,
			meter:    otel.Meter("noop"),
		}

		if err := mp.initializeMetrics(); err != nil {
			return nil, fmt.Errorf("failed to initialize noop metrics: %w", err)
		}

		return mp, nil
	}

	// Create resource
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(config.ServiceName),
			semconv.ServiceVersion(config.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	var readers []sdkmetric.Reader

	// Create Prometheus exporter for pull-based scraping
	prometheusExporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create Prometheus exporter: %w", err)
	}
	readers = append(readers, prometheusExporter)

	// Optionally create OTLP pusher if endpoint is configured
	if config.OTLPEndpoint != "" {
		opts := []otlpmetrichttp.Option{
			otlpmetrichttp.WithEndpoint(config.OTLPEndpoint),
		}
		if config.InsecureMode {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}

		otlpExporter, err := otlpmetrichttp.New(context.Background(), opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP metrics exporter: %w", err)
		}

		// Add periodic reader for pushing metrics
		readers = append(readers, sdkmetric.NewPeriodicReader(otlpExporter,
			sdkmetric.WithInterval(10*time.Second),
		))
	}

	// Create meter provider with readers
	opts := []sdkmetric.Option{
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(prometheusExporter),
	}

	// Add OTLP reader if configured
	if len(readers) > 1 {
		opts = append(opts, sdkmetric.WithReader(readers[1]))
	}

	provider := sdkmetric.NewMeterProvider(opts...)

	// Set global meter provider
	otel.SetMeterProvider(provider)

	meter := provider.Meter(config.ServiceName)

	mp := &MetricsProvider{
		provider:           provider,
		meter:              meter,
		prometheusExporter: prometheusExporter,
	}

	// Initialize metric instruments
	if err := mp.initializeMetrics(); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	return mp, nil
}

// initializeMetrics creates all metric instruments
func (mp *MetricsProvider) initializeMetrics() error {
	var err error

	// HTTP metrics
	mp.httpRequestCounter, err = mp.meter.Int64Counter(
		"http.server.request.count",
		metric.WithDescription("Total number of HTTP requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return err
	}

	mp.httpRequestDuration, err = mp.meter.Float64Histogram(
		"http.server.request.duration",
		metric.WithDescription("HTTP request duration"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	// gRPC metrics
	mp.grpcRequestCounter, err = mp.meter.Int64Counter(
		"grpc.server.call.count",
		metric.WithDescription("Total number of gRPC calls"),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		return err
	}

	mp.grpcRequestDuration, err = mp.meter.Float64Histogram(
		"grpc.server.call.duration",
		metric.WithDescription("gRPC call duration"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	// Custom business metrics
	mp.sessionsCreatedCounter, err = mp.meter.Int64Counter(
		"sts.sessions.created",
		metric.WithDescription("Total number of sessions created"),
		metric.WithUnit("{session}"),
	)
	if err != nil {
		return err
	}

	mp.tokensMintedCounter, err = mp.meter.Int64Counter(
		"sts.tokens.minted",
		metric.WithDescription("Total number of JWT tokens minted"),
		metric.WithUnit("{token}"),
	)
	if err != nil {
		return err
	}

	mp.keysRotatedCounter, err = mp.meter.Int64Counter(
		"sts.keys.rotated",
		metric.WithDescription("Total number of key rotations"),
		metric.WithUnit("{rotation}"),
	)
	if err != nil {
		return err
	}

	mp.m2mClampedTTLHistogram, err = mp.meter.Float64Histogram(
		"sts.m2m.token.clamped_ttl",
		metric.WithDescription("Clamped TTL of minted M2M tokens"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	return nil
}

// Shutdown gracefully shuts down the metrics provider
func (mp *MetricsProvider) Shutdown(ctx context.Context) error {
	if mp.provider != nil {
		return mp.provider.Shutdown(ctx)
	}
	return nil
}

// GetPrometheusHandler returns the Prometheus HTTP handler
func (mp *MetricsProvider) GetPrometheusHandler() http.Handler {
	// Use standard Prometheus HTTP handler
	return promhttp.Handler()
}

// RecordHTTPRequest records an HTTP request metric
func (mp *MetricsProvider) RecordHTTPRequest(ctx context.Context, method, path string, statusCode int, duration time.Duration) {
	attrs := []attribute.KeyValue{
		attribute.String("http.method", method),
		attribute.String("http.route", path),
		attribute.Int("http.status_code", statusCode),
	}

	mp.httpRequestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	mp.httpRequestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
}

// RecordGRPCRequest records a gRPC request metric
func (mp *MetricsProvider) RecordGRPCRequest(ctx context.Context, method string, err error, duration time.Duration) {
	code := 0 // OK
	if err != nil {
		st, _ := status.FromError(err)
		code = int(st.Code())
	}

	attrs := []attribute.KeyValue{
		attribute.String("rpc.method", method),
		attribute.String("rpc.service", "sts.v1.SecurityTokenService"),
		attribute.String("rpc.system", "grpc"),
		attribute.Int("rpc.grpc.status_code", code),
	}

	mp.grpcRequestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	mp.grpcRequestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
}

// RecordSessionCreated increments the sessions created counter
func (mp *MetricsProvider) RecordSessionCreated(ctx context.Context) {
	mp.sessionsCreatedCounter.Add(ctx, 1)
}

// RecordTokenMinted increments the tokens minted counter
func (mp *MetricsProvider) RecordTokenMinted(ctx context.Context) {
	mp.tokensMintedCounter.Add(ctx, 1)
}

// RecordM2MTokenClampedTTL records the clamped TTL for an exchanged M2M token
func (mp *MetricsProvider) RecordM2MTokenClampedTTL(ctx context.Context, ttlSeconds float64) {
	if mp.m2mClampedTTLHistogram != nil {
		mp.m2mClampedTTLHistogram.Record(ctx, ttlSeconds)
	}
}

// RecordKeyRotation increments the key rotations counter
func (mp *MetricsProvider) RecordKeyRotation(ctx context.Context) {
	mp.keysRotatedCounter.Add(ctx, 1)
}

// HTTPMetricsMiddleware wraps HTTP handlers with metrics
func HTTPMetricsMiddleware(mp *MetricsProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			wrapped := &metricsResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)
			mp.RecordHTTPRequest(r.Context(), r.Method, r.URL.Path, wrapped.statusCode, duration)
		})
	}
}

// metricsResponseWriter wraps http.ResponseWriter for metrics
type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *metricsResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// GRPCUnaryMetricsInterceptor adds metrics to gRPC unary calls
func GRPCUnaryMetricsInterceptor(mp *MetricsProvider) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		resp, err := handler(ctx, req)

		duration := time.Since(start)
		mp.RecordGRPCRequest(ctx, info.FullMethod, err, duration)

		return resp, err
	}
}
