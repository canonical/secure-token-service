// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"

	"github.com/kelseyhightower/envconfig"
)

// Config holds configuration for the Session Service (Janus).
type Config struct {
	// Database
	DatabaseURL string `envconfig:"DATABASE_URL" default:"postgres://localhost:5432/sts?sslmode=disable"`

	// Cache (Redis/Valkey)
	CacheAddr     string `envconfig:"CACHE_ADDR" default:"localhost:6379"`
	CacheUsername string `envconfig:"CACHE_USERNAME" default:""`
	CachePassword string `envconfig:"CACHE_PASSWORD" default:""`
	CacheDB       int    `envconfig:"CACHE_DB" default:"0"`

	// HTTP Server
	HTTPPort string `envconfig:"HTTP_PORT" default:"8080"`

	// gRPC Server
	GRPCPort string `envconfig:"GRPC_PORT" default:"9090"`

	// Keys
	PrivateKeyPath string `envconfig:"PRIVATE_KEY_PATH" default:"./keys/private.pem"`
	PublicKeyPath  string `envconfig:"PUBLIC_KEY_PATH" default:"./keys/public.pem"`

	// JWT Settings
	JWTIssuer     string `envconfig:"JWT_ISSUER" default:"session-service"`
	JWTAudience   string `envconfig:"JWT_AUDIENCE" default:"internal-services"`
	JWTExpiry     int    `envconfig:"JWT_EXPIRY" default:"3600"`      // seconds
	SessionExpiry int    `envconfig:"SESSION_EXPIRY" default:"86400"` // seconds (1 day)
	// Cookie Encryption
	CookieHashKey  string `envconfig:"COOKIE_HASH_KEY"`  // 64 bytes

	// OIDC Configuration
	OIDCProviderURL      string   `envconfig:"OIDC_PROVIDER_URL" required:"true"`
	OIDCClientID         string   `envconfig:"OIDC_CLIENT_ID" required:"true"`
	OIDCClientSecret     string   `envconfig:"OIDC_CLIENT_SECRET" required:"true"`
	OIDCRedirectURL      string   `envconfig:"OIDC_REDIRECT_URL" required:"true"`
	OIDCScopes           []string `envconfig:"OIDC_SCOPES" default:"openid,profile,email,offline_access"`
	AllowedReturnToHosts []string `envconfig:"ALLOWED_RETURN_TO_HOSTS" default:""`

	// Upstream Hydra JWKS Configuration
	HydraJWKSURL string `envconfig:"HYDRA_JWKS_URL" default:""`

	// JWKS Caching
	JWKSCacheTTL int `envconfig:"JWKS_CACHE_TTL" default:"600"` // seconds (10 minutes)

	// Observability
	LogLevel          string  `envconfig:"LOG_LEVEL" default:"info"`
	LogFormat         string  `envconfig:"LOG_FORMAT" default:"json"`
	MetricsEnabled    bool    `envconfig:"METRICS_ENABLED" default:"true"`
	TracingEnabled    bool    `envconfig:"TRACING_ENABLED" default:"true"`
	TracingEndpoint   string  `envconfig:"TRACING_ENDPOINT" default:""`
	TracingSampleRate float64 `envconfig:"TRACING_SAMPLE_RATE" default:"0.1"`
	ServiceName       string  `envconfig:"SERVICE_NAME" default:"secure-token-service"`
	ServiceVersion    string  `envconfig:"SERVICE_VERSION" default:"1.0.0"`
}

// HydraJWKSEndpoint returns the configured Hydra JWKS URL or derives it from OIDCProviderURL.
func (c *Config) HydraJWKSEndpoint() string {
	if c.HydraJWKSURL != "" {
		return c.HydraJWKSURL
	}
	return strings.TrimSuffix(c.OIDCProviderURL, "/") + "/.well-known/jwks.json"
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
