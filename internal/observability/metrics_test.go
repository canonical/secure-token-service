// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
