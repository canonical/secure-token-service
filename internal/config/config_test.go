// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {

	// Set required environment variables
	os.Setenv("OIDC_PROVIDER_URL", "https://example.com")
	os.Setenv("OIDC_CLIENT_ID", "test-client")
	os.Setenv("OIDC_CLIENT_SECRET", "test-secret")
	os.Setenv("OIDC_REDIRECT_URL", "http://localhost:8080/callback")
	defer func() {
		os.Unsetenv("OIDC_PROVIDER_URL")
		os.Unsetenv("OIDC_CLIENT_ID")
		os.Unsetenv("OIDC_CLIENT_SECRET")
		os.Unsetenv("OIDC_REDIRECT_URL")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}

	// Verify OIDC required fields
	if cfg.OIDCProviderURL != "https://example.com" {
		t.Errorf("OIDCProviderURL = %s, want https://example.com", cfg.OIDCProviderURL)
	}
	if cfg.OIDCClientID != "test-client" {
		t.Errorf("OIDCClientID = %s, want test-client", cfg.OIDCClientID)
	}
}

func TestLoad_Defaults(t *testing.T) {

	// Set only required fields
	os.Setenv("OIDC_PROVIDER_URL", "https://example.com")
	os.Setenv("OIDC_CLIENT_ID", "test-client")
	os.Setenv("OIDC_CLIENT_SECRET", "test-secret")
	os.Setenv("OIDC_REDIRECT_URL", "http://localhost:8080/callback")
	defer func() {
		os.Unsetenv("OIDC_PROVIDER_URL")
		os.Unsetenv("OIDC_CLIENT_ID")
		os.Unsetenv("OIDC_CLIENT_SECRET")
		os.Unsetenv("OIDC_REDIRECT_URL")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify default values
	if cfg.HTTPPort != "8080" {
		t.Errorf("HTTPPort = %s, want 8080", cfg.HTTPPort)
	}
	if cfg.GRPCPort != "9090" {
		t.Errorf("GRPCPort = %s, want 9090", cfg.GRPCPort)
	}
	if cfg.JWTIssuer != "session-service" {
		t.Errorf("JWTIssuer = %s, want session-service", cfg.JWTIssuer)
	}
	if cfg.JWTAudience != "internal-services" {
		t.Errorf("JWTAudience = %s, want internal-services", cfg.JWTAudience)
	}
	if cfg.JWTExpiry != 3600 {
		t.Errorf("JWTExpiry = %d, want 3600", cfg.JWTExpiry)
	}
	if cfg.SessionExpiry != 86400 {
		t.Errorf("SessionExpiry = %d, want 86400", cfg.SessionExpiry)
	}
	if cfg.CacheAddr != "localhost:6379" {
		t.Errorf("CacheAddr = %s, want localhost:6379", cfg.CacheAddr)
	}
	if cfg.CacheUsername != "" {
		t.Errorf("CacheUsername = %s, want empty string", cfg.CacheUsername)
	}
	if cfg.CacheDB != 0 {
		t.Errorf("CacheDB = %d, want 0", cfg.CacheDB)
	}
	if cfg.JWKSCacheTTL != 600 {
		t.Errorf("JWKSCacheTTL = %d, want 600", cfg.JWKSCacheTTL)
	}
	if cfg.MetricsEnabled != true {
		t.Errorf("MetricsEnabled = %t, want true", cfg.MetricsEnabled)
	}
	if cfg.TracingEnabled != true {
		t.Errorf("TracingEnabled = %t, want true", cfg.TracingEnabled)
	}
	if cfg.TracingSampleRate != 0.1 {
		t.Errorf("TracingSampleRate = %f, want 0.1", cfg.TracingSampleRate)
	}
	if cfg.ServiceName != "secure-token-service" {
		t.Errorf("ServiceName = %s, want secure-token-service", cfg.ServiceName)
	}
}

func TestLoad_CustomValues(t *testing.T) {

	// Set custom values
	os.Setenv("OIDC_PROVIDER_URL", "https://custom.example.com")
	os.Setenv("OIDC_CLIENT_ID", "custom-client")
	os.Setenv("OIDC_CLIENT_SECRET", "custom-secret")
	os.Setenv("OIDC_REDIRECT_URL", "https://app.example.com/auth/callback")
	os.Setenv("HTTP_PORT", "9000")
	os.Setenv("GRPC_PORT", "9001")
	os.Setenv("JWT_ISSUER", "custom-issuer")
	os.Setenv("JWT_AUDIENCE", "custom-audience")
	os.Setenv("JWT_EXPIRY", "7200")
	os.Setenv("CACHE_ADDR", "cache.example.com:6379")
	os.Setenv("CACHE_USERNAME", "cache-user")
	os.Setenv("CACHE_DB", "1")
	os.Setenv("CACHE_PASSWORD", "secret-password")
	os.Setenv("JWKS_CACHE_TTL", "1200")
	os.Setenv("SESSION_EXPIRY", "172800")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("LOG_FORMAT", "text")
	os.Setenv("METRICS_ENABLED", "false")
	os.Setenv("TRACING_ENABLED", "false")
	defer func() {
		os.Unsetenv("OIDC_PROVIDER_URL")
		os.Unsetenv("OIDC_CLIENT_ID")
		os.Unsetenv("OIDC_CLIENT_SECRET")
		os.Unsetenv("OIDC_REDIRECT_URL")
		os.Unsetenv("HTTP_PORT")
		os.Unsetenv("GRPC_PORT")
		os.Unsetenv("JWT_ISSUER")
		os.Unsetenv("JWT_AUDIENCE")
		os.Unsetenv("JWT_EXPIRY")
		os.Unsetenv("CACHE_ADDR")
		os.Unsetenv("CACHE_USERNAME")
		os.Unsetenv("CACHE_DB")
		os.Unsetenv("CACHE_PASSWORD")
		os.Unsetenv("JWKS_CACHE_TTL")
		os.Unsetenv("LOG_LEVEL")
		os.Unsetenv("LOG_FORMAT")
		os.Unsetenv("METRICS_ENABLED")
		os.Unsetenv("TRACING_ENABLED")
		os.Unsetenv("SESSION_EXPIRY")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify custom values
	if cfg.HTTPPort != "9000" {
		t.Errorf("HTTPPort = %s, want 9000", cfg.HTTPPort)
	}
	if cfg.GRPCPort != "9001" {
		t.Errorf("GRPCPort = %s, want 9001", cfg.GRPCPort)
	}
	if cfg.JWTIssuer != "custom-issuer" {
		t.Errorf("JWTIssuer = %s, want custom-issuer", cfg.JWTIssuer)
	}
	if cfg.JWTAudience != "custom-audience" {
		t.Errorf("JWTAudience = %s, want custom-audience", cfg.JWTAudience)
	}
	if cfg.JWTExpiry != 7200 {
		t.Errorf("JWTExpiry = %d, want 7200", cfg.JWTExpiry)
	}
	if cfg.SessionExpiry != 172800 {
		t.Errorf("SessionExpiry = %d, want 172800", cfg.SessionExpiry)
	}
	if cfg.CacheAddr != "cache.example.com:6379" {
		t.Errorf("CacheAddr = %s, want cache.example.com:6379", cfg.CacheAddr)
	}
	if cfg.CacheUsername != "cache-user" {
		t.Errorf("CacheUsername = %s, want cache-user", cfg.CacheUsername)
	}
	if cfg.CacheDB != 1 {
		t.Errorf("CacheDB = %d, want 1", cfg.CacheDB)
	}
	if cfg.CachePassword != "secret-password" {
		t.Errorf("CachePassword = %s, want secret-password", cfg.CachePassword)
	}
	if cfg.JWKSCacheTTL != 1200 {
		t.Errorf("JWKSCacheTTL = %d, want 1200", cfg.JWKSCacheTTL)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %s, want debug", cfg.LogLevel)
	}
	if cfg.LogFormat != "text" {
		t.Errorf("LogFormat = %s, want text", cfg.LogFormat)
	}
	if cfg.MetricsEnabled != false {
		t.Errorf("MetricsEnabled = %t, want false", cfg.MetricsEnabled)
	}
	if cfg.TracingEnabled != false {
		t.Errorf("TracingEnabled = %t, want false", cfg.TracingEnabled)
	}
}

func TestLoad_MissingRequiredFields(t *testing.T) {

	// Don't set any environment variables
	tests := []struct {
		name    string
		setVars func()
	}{
		{
			name: "missing all required fields",
			setVars: func() {
				// Don't set anything
			},
		},
		{
			name: "missing OIDC_CLIENT_ID",
			setVars: func() {
				os.Setenv("OIDC_PROVIDER_URL", "https://example.com")
				os.Setenv("OIDC_CLIENT_SECRET", "secret")
				os.Setenv("OIDC_REDIRECT_URL", "http://localhost/callback")
			},
		},
		{
			name: "missing OIDC_CLIENT_SECRET",
			setVars: func() {
				os.Setenv("OIDC_PROVIDER_URL", "https://example.com")
				os.Setenv("OIDC_CLIENT_ID", "client")
				os.Setenv("OIDC_REDIRECT_URL", "http://localhost/callback")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean environment
			os.Clearenv()

			// Set test-specific vars
			tt.setVars()

			_, err := Load()
			if err == nil {
				t.Error("Load() should fail with missing required fields, but succeeded")
			}
		})
	}
}
