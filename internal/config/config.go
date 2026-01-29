// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package config

import (
	"github.com/kelseyhightower/envconfig"
)

// Config holds configuration for the Session Service (Janus).
type Config struct {
	// Database
	DatabaseURL string `envconfig:"DATABASE_URL" default:"postgres://localhost:5432/sts?sslmode=disable"`

	// Cache (Redis/Valkey)
	CacheAddr     string `envconfig:"CACHE_ADDR" default:"localhost:6379"`
	CachePassword string `envconfig:"CACHE_PASSWORD" default:""`
	CacheDB       int    `envconfig:"CACHE_DB" default:"0"`

	// HTTP Server
	HTTPPort string `envconfig:"HTTP_PORT" default:"8080"`

	// gRPC Server
	GRPCPort string `envconfig:"GRPC_PORT" default:"9090"`

	// RSA Keys
	PrivateKeyPath string `envconfig:"PRIVATE_KEY_PATH" default:"./keys/private.pem"`
	PublicKeyPath  string `envconfig:"PUBLIC_KEY_PATH" default:"./keys/public.pem"`

	// JWT Settings
	JWTIssuer   string `envconfig:"JWT_ISSUER" default:"session-service"`
	JWTAudience string `envconfig:"JWT_AUDIENCE" default:"internal-services"`
	JWTExpiry   int    `envconfig:"JWT_EXPIRY" default:"3600"` // seconds
	// Cookie Encryption
	CookieHashKey  string `envconfig:"COOKIE_HASH_KEY" default:"0123456789012345678901234567890123456789012345678901234567890123"` // 64 bytes
	CookieBlockKey string `envconfig:"COOKIE_BLOCK_KEY" default:"01234567890123456789012345678901"`                                // 32 bytes
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
