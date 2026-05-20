// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"context"
	"fmt"

	"github.com/canonical/secure-token-service/internal/config"
)

// Observability holds all observability components
type Observability struct {
	Logger          *Logger
	MetricsProvider *MetricsProvider
	TracerProvider  *TracerProvider
}

// Initialize creates and initializes all observability components based on configuration
func Initialize(ctx context.Context, cfg *config.Config) (*Observability, error) {
	// Initialize logger
	logger, err := NewLogger(cfg.LogLevel, false)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Initialize metrics
	metricsConfig := MetricsConfig{
		Enabled:        cfg.MetricsEnabled,
		ServiceName:    cfg.ServiceName,
		ServiceVersion: cfg.ServiceVersion,
		OTLPEndpoint:   "", // Use Prometheus pull only by default
		InsecureMode:   true,
	}
	metricsProvider, err := NewMetricsProvider(metricsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	// Initialize tracing
	tracingConfig := TracingConfig{
		Enabled:        cfg.TracingEnabled,
		ServiceName:    cfg.ServiceName,
		ServiceVersion: cfg.ServiceVersion,
		OTLPEndpoint:   cfg.TracingEndpoint,
		InsecureMode:   true,
		SamplingRatio:  cfg.TracingSampleRate,
	}
	tracerProvider, err := NewTracerProvider(tracingConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tracing: %w", err)
	}

	return &Observability{
		Logger:          logger,
		MetricsProvider: metricsProvider,
		TracerProvider:  tracerProvider,
	}, nil
}

// Shutdown gracefully shuts down all observability components
func (o *Observability) Shutdown(ctx context.Context) error {
	if o.Logger != nil {
		_ = o.Logger.Sync()
	}
	if o.MetricsProvider != nil {
		if err := o.MetricsProvider.Shutdown(ctx); err != nil {
			return err
		}
	}
	if o.TracerProvider != nil {
		if err := o.TracerProvider.Shutdown(ctx); err != nil {
			return err
		}
	}
	return nil
}
