// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"
)

func TestNewMetricsProviderDisabled(t *testing.T) {
	mp, err := NewMetricsProvider(MetricsConfig{Enabled: false})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if mp == nil {
		t.Fatal("expected non-nil MetricsProvider")
	}

	if mp.provider != nil {
		t.Error("expected nil provider for disabled metrics")
	}

	if mp.httpRequestCounter == nil {
		t.Error("expected httpRequestCounter to be initialized")
	}

	if mp.httpRequestDuration == nil {
		t.Error("expected httpRequestDuration to be initialized")
	}

	if mp.grpcRequestCounter == nil {
		t.Error("expected grpcRequestCounter to be initialized")
	}

	if mp.grpcRequestDuration == nil {
		t.Error("expected grpcRequestDuration to be initialized")
	}

	if mp.sessionsCreatedCounter == nil {
		t.Error("expected sessionsCreatedCounter to be initialized")
	}

	if mp.tokensMintedCounter == nil {
		t.Error("expected tokensMintedCounter to be initialized")
	}

	if mp.keysRotatedCounter == nil {
		t.Error("expected keysRotatedCounter to be initialized")
	}

	if mp.m2mClampedTTLHistogram == nil {
		t.Error("expected m2mClampedTTLHistogram to be initialized")
	}
}

func TestRecordHTTPRequestDisabledMetrics(t *testing.T) {
	mp, err := NewMetricsProvider(MetricsConfig{Enabled: false})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should not panic
	mp.RecordHTTPRequest(context.Background(), "GET", "/test", http.StatusOK, time.Second)
}

func TestRecordGRPCRequestDisabledMetrics(t *testing.T) {
	mp, err := NewMetricsProvider(MetricsConfig{Enabled: false})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should not panic
	mp.RecordGRPCRequest(context.Background(), "/test.Service/Method", nil, time.Second)
}

func TestRecordBusinessMetricsDisabledMetrics(t *testing.T) {
	mp, err := NewMetricsProvider(MetricsConfig{Enabled: false})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	ctx := context.Background()

	// Should not panic
	mp.RecordSessionCreated(ctx)
	mp.RecordTokenMinted(ctx)
	mp.RecordKeyRotation(ctx)
	mp.RecordM2MTokenClampedTTL(ctx, 300.0)
}

func TestHTTPMetricsMiddlewareDisabledMetrics(t *testing.T) {
	mp, err := NewMetricsProvider(MetricsConfig{Enabled: false})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	handler := HTTPMetricsMiddleware(mp)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	// Should not panic
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestGRPCUnaryMetricsInterceptorDisabledMetrics(t *testing.T) {
	mp, err := NewMetricsProvider(MetricsConfig{Enabled: false})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	interceptor := GRPCUnaryMetricsInterceptor(mp)

	// Should not panic
	resp, err := interceptor(
		context.Background(),
		nil,
		&grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"},
		func(ctx context.Context, req interface{}) (interface{}, error) {
			return "ok", nil
		},
	)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if resp != "ok" {
		t.Errorf("expected response 'ok', got %v", resp)
	}
}

func TestShutdownDisabledMetrics(t *testing.T) {
	mp, err := NewMetricsProvider(MetricsConfig{Enabled: false})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should not panic or return error
	if err := mp.Shutdown(context.Background()); err != nil {
		t.Errorf("expected no error on shutdown, got %v", err)
	}
}

func TestHTTPMetricsMiddlewareUsesChiRoutePattern(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
	})

	mp := &MetricsProvider{
		provider: provider,
		meter:    provider.Meter("test-sts"),
	}
	if err := mp.initializeMetrics(); err != nil {
		t.Fatalf("initializeMetrics failed: %v", err)
	}

	r := chi.NewRouter()
	r.Use(HTTPMetricsMiddleware(mp))
	r.Delete("/auth/sessions/{session_id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rawUUIDPath := "/auth/sessions/550e8400-e29b-41d4-a716-446655440000"
	req := httptest.NewRequest(http.MethodDelete, rawUUIDPath, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	// Also test an unmatched 404 route to ensure bounded cardinality.
	req404 := httptest.NewRequest(http.MethodGet, "/unknown/random-id-12345", nil)
	rec404 := httptest.NewRecorder()
	r.ServeHTTP(rec404, req404)
	if rec404.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", rec404.Code)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	routes := make(map[string]int64)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "http.server.request.count" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("unexpected metric data type %T", m.Data)
			}
			for _, dp := range sum.DataPoints {
				if val, ok := dp.Attributes.Value(attribute.Key("http.route")); ok {
					routes[val.AsString()] += dp.Value
				}
			}
		}
	}

	if routes["/auth/sessions/{session_id}"] != 1 {
		t.Errorf("expected http.route=\"/auth/sessions/{session_id}\" count=1, got routes=%v", routes)
	}
	if _, leaked := routes[rawUUIDPath]; leaked {
		t.Errorf("raw UUID path %q leaked into http.route metric label: %v", rawUUIDPath, routes)
	}
	if routes["unmatched"] != 1 {
		t.Errorf("expected http.route=\"unmatched\" count=1 for 404, got routes=%v", routes)
	}
}
