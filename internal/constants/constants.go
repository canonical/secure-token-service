// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

// Package constants defines application-wide constants for the Secure Token Service.
package constants

import "time"

// Cookie configuration constants
const (
	// CookieMaxAge is the maximum age for session and OIDC state cookies (10 minutes)
	CookieMaxAge = 600 // seconds

	// CookieName is the name of the session cookie
	CookieName = "session_id"

	// OIDCStateCookieName is the name of the OIDC state cookie
	OIDCStateCookieName = "oauth_state"

	// OIDCNonceCookieName is the name of the OIDC nonce cookie
	OIDCNonceCookieName = "oauth_nonce"
)

// Session configuration constants
const (
	// DefaultSessionTTL is the default time-to-live for sessions (1 hour)
	DefaultSessionTTL = 1 * time.Hour

	// DefaultJWTExpiry is the default expiry for minted JWTs  (15 minutes)
	DefaultJWTExpiry = 15 * time.Minute
)

// Cache configuration constants
const (
	// DefaultJWKSCacheTTL is the default TTL for JWKS cache in Valkey (10 minutes)
	DefaultJWKSCacheTTL = 600 // seconds

	// JWKSCacheKey is the cache key for JWKS data
	JWKSCacheKey = "jwks:all"

	// HTTPCacheMaxAge is the Cache-Control max-age for JWKS HTTP endpoint (5 minutes)
	HTTPCacheMaxAge = 300 // seconds
)

// Database configuration constants
const (
	// DefaultDBMaxConns is the default maximum number of database connections
	DefaultDBMaxConns = 25

	// DefaultDBMinConns is the default minimum number of idle connections in the pool
	DefaultDBMinConns = 5

	// DefaultDBMaxConnLifetime is the maximum lifetime of a connection
	DefaultDBMaxConnLifetime = 1 * time.Hour

	// DefaultDBMaxConnIdleTime is the maximum idle time for a connection
	DefaultDBMaxConnIdleTime = 30 * time.Minute
)

// Server configuration constants
const (
	// DefaultHTTPPort is the default port for the HTTP server
	DefaultHTTPPort = "8080"

	// DefaultGRPCPort is the default port for the gRPC server
	DefaultGRPCPort = "9090"

	// GracefulShutdownTimeout is the timeout for graceful shutdown
	GracefulShutdownTimeout = 30 * time.Second
)

// Key management constants
const (
	// RSAKeySize is the size of RSA keys for JWT signing (2048 bits)
	RSAKeySize = 2048

	// JWTSigningAlgorithm is the algorithm used for JWT signing
	JWTSigningAlgorithm = "RS256"

	// JWKKeyUsage is the usage type for JWK keys
	JWKKeyUsage = "sig"

	// JWKKeyType is the key type for JWK keys
	JWKKeyType = "RSA"
)

// OIDC configuration constants
const (
	// OIDCStateLength is the length of the OIDC state parameter
	OIDCStateLength = 32

	// OIDCNonceLength is the length of the OIDC nonce parameter
	OIDCNonceLength = 32
)
