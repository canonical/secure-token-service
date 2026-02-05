// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package observability

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TracingConfig holds tracing configuration
type TracingConfig struct {
	Enabled        bool
	ServiceName    string
	ServiceVersion string
	OTLPEndpoint   string // e.g., "localhost:4318"
	InsecureMode   bool
	SamplingRatio  float64 // 0.0 to 1.0
}

// TracerProvider wraps OpenTelemetry tracer provider
type TracerProvider struct {
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
}

// NewTracerProvider creates a new OpenTelemetry tracer provider with OTLP exporter
func NewTracerProvider(config TracingConfig) (*TracerProvider, error) {
	if !config.Enabled {
		// Return no-op tracer
		return &TracerProvider{
			provider: nil,
			tracer:   otel.Tracer("noop"),
		}, nil
	}

	// Create OTLP HTTP exporter
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(config.OTLPEndpoint),
	}
	if config.InsecureMode {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	exporter, err := otlptracehttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
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

	// Create tracer provider with sampling
	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(config.SamplingRatio))
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set global tracer provider
	otel.SetTracerProvider(provider)

	// Set global propagator for W3C Trace Context
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer := provider.Tracer(config.ServiceName)

	return &TracerProvider{
		provider: provider,
		tracer:   tracer,
	}, nil
}

// Shutdown gracefully shuts down the tracer provider
func (tp *TracerProvider) Shutdown(ctx context.Context) error {
	if tp.provider != nil {
		return tp.provider.Shutdown(ctx)
	}
	return nil
}

// Tracer returns the tracer instance
func (tp *TracerProvider) Tracer() trace.Tracer {
	return tp.tracer
}

// HTTPTracingMiddleware wraps HTTP handlers with tracing
func HTTPTracingMiddleware(tracer trace.Tracer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract trace context from headers
			ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			// Start span with rich attributes
			ctx, span := tracer.Start(ctx, fmt.Sprintf("HTTP %s %s", r.Method, r.URL.Path),
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					attribute.String(string(semconv.HTTPRequestMethodKey), r.Method),
					attribute.String(string(semconv.HTTPRouteKey), r.URL.Path),
					attribute.String(string(semconv.URLSchemeKey), r.URL.Scheme),
					attribute.String(string(semconv.URLPathKey), r.URL.RequestURI()),
					attribute.String(string(semconv.UserAgentOriginalKey), r.UserAgent()),
					attribute.String(string(semconv.NetworkPeerAddressKey), r.RemoteAddr),
					attribute.String("http.client_ip", getClientIP(r)),
				),
			)
			defer span.End()

			// Add request ID if available
			if requestID := GetRequestID(ctx); requestID != "" {
				span.SetAttributes(attribute.String("request.id", requestID))
			}

			// Wrap response writer to capture status code
			wrapped := &tracingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Continue with request
			r = r.WithContext(ctx)
			next.ServeHTTP(wrapped, r)

			// Set response attributes
			span.SetAttributes(
				attribute.Int(string(semconv.HTTPResponseStatusCodeKey), wrapped.statusCode),
				attribute.Int("http.response.body.size", wrapped.written),
			)

			// Set span status based on HTTP status code
			if wrapped.statusCode >= 400 {
				span.SetAttributes(attribute.Bool("error", true))
			}
		})
	}
}

// tracingResponseWriter wraps http.ResponseWriter for tracing
type tracingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    int
}

func (rw *tracingResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *tracingResponseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.written += n
	return n, err
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Try X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Try X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// GRPCUnaryTracingInterceptor adds tracing to gRPC unary calls
func GRPCUnaryTracingInterceptor(tracer trace.Tracer) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Extract trace context from gRPC metadata
		md, _ := metadata.FromIncomingContext(ctx)
		ctx = otel.GetTextMapPropagator().Extract(ctx, &metadataCarrier{md: md})

		// Start span with rich attributes
		ctx, span := tracer.Start(ctx, info.FullMethod,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.method", info.FullMethod),
				attribute.String("rpc.service", "sts.v1.SecurityTokenService"),
			),
		)
		defer span.End()

		// Add request ID if available
		if requestID := GetRequestID(ctx); requestID != "" {
			span.SetAttributes(attribute.String("request.id", requestID))
		}

		// Call handler
		start := time.Now()
		resp, err := handler(ctx, req)
		duration := time.Since(start)

		// Set response attributes
		span.SetAttributes(attribute.Int64("rpc.duration_ms", duration.Milliseconds()))

		if err != nil {
			// Extract gRPC status
			st, _ := status.FromError(err)
			span.SetAttributes(
				attribute.Int("rpc.grpc.status_code", int(st.Code())),
				attribute.String("rpc.grpc.status_message", st.Message()),
				attribute.Bool("error", true),
			)
		} else {
			span.SetAttributes(attribute.Int("rpc.grpc.status_code", 0)) // OK
		}

		return resp, err
	}
}

// metadataCarrier adapts metadata.MD to propagation.TextMapCarrier
type metadataCarrier struct {
	md metadata.MD
}

func (mc *metadataCarrier) Get(key string) string {
	values := mc.md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (mc *metadataCarrier) Set(key, value string) {
	mc.md.Set(key, value)
}

func (mc *metadataCarrier) Keys() []string {
	keys := make([]string, 0, len(mc.md))
	for k := range mc.md {
		keys = append(keys, k)
	}
	return keys
}

// SpanFromContext extracts span from context
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// AddSpanAttributes adds attributes to the current span
func AddSpanAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attrs...)
}

// AddSpanEvent adds an event to the current span
func AddSpanEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, trace.WithAttributes(attrs...))
}
