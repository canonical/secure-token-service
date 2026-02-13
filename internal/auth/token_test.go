// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package auth

//go:generate mockgen -build_flags=--mod=mod -package=auth -destination=./mock_repository.go -source=../db/jwks_repository.go

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/canonical/secure-token-service/internal/db"
	"github.com/golang-jwt/jwt/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/testcontainers/testcontainers-go/modules/valkey"
	valkeygo "github.com/valkey-io/valkey-go"
)

// sanitizeName converts test names to valid container names
// Container names must match: [a-zA-Z0-9][a-zA-Z0-9_.-]*
func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ToLower(name)
	return name
}

func setupTestPostgres(t *testing.T) (*db.PostgresJWKSRepository, *postgres.PostgresContainer) {
	ctx := context.Background()

	// Start PostgreSQL container with unique name based on test name
	containerName := fmt.Sprintf("sts-auth-pg-%s", sanitizeName(t.Name()))
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name: containerName,
			},
		}),
	)
	if err != nil {
		t.Fatalf("Failed to start PostgreSQL container: %v", err)
	}

	// Get connection string
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("Failed to get connection string: %v", err)
	}

	// Retry connection until PostgreSQL is ready
	var database *db.DB
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		database, err = db.NewDB(ctx, connStr)
		if err == nil {
			break
		}
		if i < maxRetries-1 {
			time.Sleep(time.Second)
		}
	}
	if err != nil {
		t.Fatalf("Failed to connect to database after %d retries: %v", maxRetries, err)
	}

	// Run migrations - create hydra_jwk table
	migrationSQL := `
		CREATE TABLE IF NOT EXISTS hydra_jwk (
			sid VARCHAR(255) NOT NULL,
			kid VARCHAR(255) NOT NULL,
			version INTEGER NOT NULL DEFAULT 0,
			keydata JSONB NOT NULL,
			created_at TIMESTAMP NOT NULL,
			PRIMARY KEY (sid, kid)
		);
		CREATE INDEX IF NOT EXISTS idx_hydra_jwk_sid ON hydra_jwk(sid);
	`

	_, err = database.Pool().Exec(ctx, migrationSQL)
	if err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Create repository
	repo := db.NewPostgresJWKSRepository(database.Pool())

	return repo, pgContainer
}

func setupTestValkey(t *testing.T) (valkeygo.Client, *valkey.ValkeyContainer) {
	ctx := context.Background()

	// Start Valkey container with unique name based on test name
	containerName := fmt.Sprintf("sts-auth-valkey-%s", sanitizeName(t.Name()))
	valkeyContainer, err := valkey.Run(ctx, "valkey/valkey:7.2-alpine",
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name: containerName,
			},
		}),
	)
	if err != nil {
		t.Fatalf("Failed to start Valkey container: %v", err)
	}

	// Get the host and port
	host, err := valkeyContainer.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get container host: %v", err)
	}

	port, err := valkeyContainer.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatalf("Failed to get container port: %v", err)
	}

	// Create valkey client
	valkeyClient, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress: []string{host + ":" + port.Port()},
	})
	if err != nil {
		t.Fatalf("Failed to create valkey client: %v", err)
	}

	return valkeyClient, valkeyContainer
}

// Test KeyManager initialization
func TestNewKeyManager(t *testing.T) {
	t.Parallel()
	repo, pgContainer := setupTestPostgres(t)
	defer func() {
		if err := pgContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()

	// Test with caching disabled
	km, err := NewKeyManager(ctx, repo, nil, 0)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}

	if km == nil {
		t.Fatal("KeyManager should not be nil")
	}

	// Verify initial key was generated
	key, err := repo.GetLatestActiveKey(ctx)
	if err != nil {
		t.Fatalf("Failed to get latest active key: %v", err)
	}

	if key.KID == "" {
		t.Error("Expected KID to be set")
	}
}

// Test KeyManager with caching enabled
func TestNewKeyManager_WithCaching(t *testing.T) {
	t.Parallel()
	repo, pgContainer := setupTestPostgres(t)
	defer func() {
		if err := pgContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	valkeyClient, valkeyContainer := setupTestValkey(t)
	defer func() {
		if err := valkeyContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()
	cacheTTL := 10 * time.Second

	km, err := NewKeyManager(ctx, repo, valkeyClient, cacheTTL)
	if err != nil {
		t.Fatalf("Failed to create KeyManager with caching: %v", err)
	}

	if km.cacheClient == nil {
		t.Error("Cache client should be set")
	}

	if km.cacheTTL != cacheTTL {
		t.Errorf("Cache TTL mismatch: got %v, want %v", km.cacheTTL, cacheTTL)
	}
}

// Test MintToken functionality
func TestKeyManager_MintToken(t *testing.T) {
	t.Parallel()
	repo, pgContainer := setupTestPostgres(t)
	defer func() {
		if err := pgContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()
	km, err := NewKeyManager(ctx, repo, nil, 0)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}

	// Test minting a token
	subject := "user123"
	issuer := "test-issuer"
	audience := "test-audience"
	expirySeconds := 3600
	customClaims := map[string]interface{}{
		"email": "test@example.com",
		"role":  "admin",
	}

	tokenString, err := km.MintToken(subject, issuer, audience, expirySeconds, customClaims)
	if err != nil {
		t.Fatalf("Failed to mint token: %v", err)
	}

	if tokenString == "" {
		t.Fatal("Token string should not be empty")
	}

	// Parse and verify token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Get public key for verification
		publicKey, err := km.GetPublicKey()
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	})

	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	if !token.Valid {
		t.Error("Token should be valid")
	}

	// Verify claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Failed to get claims")
	}

	if claims["sub"] != subject {
		t.Errorf("Subject mismatch: got %v, want %v", claims["sub"], subject)
	}

	if claims["iss"] != issuer {
		t.Errorf("Issuer mismatch: got %v, want %v", claims["iss"], issuer)
	}

	if claims["aud"] != audience {
		t.Errorf("Audience mismatch: got %v, want %v", claims["aud"], audience)
	}

	if claims["email"] != "test@example.com" {
		t.Error("Custom claim 'email' not found or incorrect")
	}

	if claims["role"] != "admin" {
		t.Error("Custom claim 'role' not found or incorrect")
	}

	// Verify KID in header
	kid, ok := token.Header["kid"]
	if !ok {
		t.Error("KID should be present in token header")
	}
	if kid == "" {
		t.Error("KID should not be empty")
	}
}

// Test GetPublicKey
func TestKeyManager_GetPublicKey(t *testing.T) {
	t.Parallel()
	repo, pgContainer := setupTestPostgres(t)
	defer func() {
		if err := pgContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()
	km, err := NewKeyManager(ctx, repo, nil, 0)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}

	publicKey, err := km.GetPublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	if publicKey == nil {
		t.Fatal("Public key should not be nil")
	}

	// Verify it's an RSA key
	if publicKey.N == nil {
		t.Error("Public key modulus should not be nil")
	}
}

// Test GetJWK
func TestKeyManager_GetJWK(t *testing.T) {
	t.Parallel()
	repo, pgContainer := setupTestPostgres(t)
	defer func() {
		if err := pgContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()
	km, err := NewKeyManager(ctx, repo, nil, 0)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}

	jwkKey, err := km.GetJWK()
	if err != nil {
		t.Fatalf("Failed to get JWK: %v", err)
	}

	if jwkKey == nil {
		t.Fatal("JWK key should not be nil")
	}

	// Verify metadata
	kid := jwkKey.KeyID()
	if kid == "" {
		t.Error("JWK should have a key ID")
	}

	alg := jwkKey.Algorithm()
	if alg.String() != "RS256" {
		t.Errorf("Algorithm mismatch: got %v, want RS256", alg)
	}

	usage := jwkKey.KeyUsage()
	if usage != "sig" {
		t.Errorf("Key usage mismatch: got %v, want sig", usage)
	}
}

// Test GetAllJWKS with cache miss (cold cache)
func TestKeyManager_GetAllJWKS_CacheMiss(t *testing.T) {
	t.Parallel()
	repo, pgContainer := setupTestPostgres(t)
	defer func() {
		if err := pgContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	valkeyClient, valkeyContainer := setupTestValkey(t)
	defer func() {
		if err := valkeyContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()
	cacheTTL := 10 * time.Second

	km, err := NewKeyManager(ctx, repo, valkeyClient, cacheTTL)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}

	// First call should be a cache miss
	jwkSet, err := km.GetAllJWKS()
	if err != nil {
		t.Fatalf("Failed to get cached JWKS: %v", err)
	}

	if jwkSet == nil {
		t.Fatal("JWKS should not be nil")
	}

	if jwkSet.Len() < 1 {
		t.Error("JWKS should contain at least one key")
	}

	// Verify cache was populated by checking Valkey directly
	cachedData, err := valkeyClient.Do(ctx, valkeyClient.B().Get().Key(jwksCacheKey).Build()).AsBytes()
	if err != nil {
		t.Errorf("Cache should be populated after first call: %v", err)
	}

	if len(cachedData) == 0 {
		t.Error("Cached data should not be empty")
	}
}

// Test GetAllJWKS with cache hit (warm cache)
func TestKeyManager_GetAllJWKS_CacheHit(t *testing.T) {
	t.Parallel()
	repo, pgContainer := setupTestPostgres(t)
	defer func() {
		if err := pgContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	valkeyClient, valkeyContainer := setupTestValkey(t)
	defer func() {
		if err := valkeyContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()
	cacheTTL := 10 * time.Second

	km, err := NewKeyManager(ctx, repo, valkeyClient, cacheTTL)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}

	// First call to populate cache
	jwkSet1, err := km.GetAllJWKS()
	if err != nil {
		t.Fatalf("Failed to get cached JWKS (first call): %v", err)
	}

	// Second call should hit cache
	jwkSet2, err := km.GetAllJWKS()
	if err != nil {
		t.Fatalf("Failed to get cached JWKS (second call): %v", err)
	}

	// Both should return the same data
	if jwkSet1.Len() != jwkSet2.Len() {
		t.Errorf("JWKS length mismatch: first=%d, second=%d", jwkSet1.Len(), jwkSet2.Len())
	}

	// Verify the key IDs match
	key1, _ := jwkSet1.Key(0)
	key2, _ := jwkSet2.Key(0)

	if key1.KeyID() != key2.KeyID() {
		t.Errorf("Key IDs don't match: first=%s, second=%s", key1.KeyID(), key2.KeyID())
	}
}

// Test cache invalidation
func TestKeyManager_InvalidateJWKSCache(t *testing.T) {
	t.Parallel()
	repo, pgContainer := setupTestPostgres(t)
	defer func() {
		if err := pgContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	valkeyClient, valkeyContainer := setupTestValkey(t)
	defer func() {
		if err := valkeyContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()
	cacheTTL := 10 * time.Second

	km, err := NewKeyManager(ctx, repo, valkeyClient, cacheTTL)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}

	// Populate cache
	_, err = km.GetAllJWKS()
	if err != nil {
		t.Fatalf("Failed to populate cache: %v", err)
	}

	// Verify cache exists
	cachedData, err := valkeyClient.Do(ctx, valkeyClient.B().Get().Key(jwksCacheKey).Build()).AsBytes()
	if err != nil || len(cachedData) == 0 {
		t.Fatal("Cache should be populated before invalidation")
	}

	// Invalidate cache
	err = km.InvalidateJWKSCache(ctx)
	if err != nil {
		t.Fatalf("Failed to invalidate cache: %v", err)
	}

	// Verify cache is cleared
	cachedData, err = valkeyClient.Do(ctx, valkeyClient.B().Get().Key(jwksCacheKey).Build()).AsBytes()
	if err == nil && len(cachedData) > 0 {
		t.Error("Cache should be empty after invalidation")
	}
}

// Test caching disabled (nil client)
func TestKeyManager_GetAllJWKS_CachingDisabled(t *testing.T) {
	t.Parallel()
	repo, pgContainer := setupTestPostgres(t)
	defer func() {
		if err := pgContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()

	// Create KeyManager with nil cache client
	km, err := NewKeyManager(ctx, repo, nil, 0)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}

	// Should still work, but use database directly
	jwkSet, err := km.GetAllJWKS()
	if err != nil {
		t.Fatalf("Failed to get JWKS without caching: %v", err)
	}

	if jwkSet == nil {
		t.Fatal("JWKS should not be nil")
	}

	if jwkSet.Len() < 1 {
		t.Error("JWKS should contain at least one key")
	}
}

// Test cache TTL expiry
func TestKeyManager_GetAllJWKS_TTLExpiry(t *testing.T) {
	t.Parallel()
	// Skip in short test mode
	if testing.Short() {
		t.Skip("Skipping TTL test in short mode")
	}

	repo, pgContainer := setupTestPostgres(t)
	defer func() {
		if err := pgContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	valkeyClient, valkeyContainer := setupTestValkey(t)
	defer func() {
		if err := valkeyContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()
	// Short TTL for testing
	cacheTTL := 2 * time.Second

	km, err := NewKeyManager(ctx, repo, valkeyClient, cacheTTL)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}

	// Populate cache
	_, err = km.GetAllJWKS()
	if err != nil {
		t.Fatalf("Failed to populate cache: %v", err)
	}

	// Verify cache exists
	cachedData, err := valkeyClient.Do(ctx, valkeyClient.B().Get().Key(jwksCacheKey).Build()).AsBytes()
	if err != nil || len(cachedData) == 0 {
		t.Fatal("Cache should be populated")
	}

	// Wait for TTL to expire
	time.Sleep(3 * time.Second)

	// Verify cache expired
	cachedData, err = valkeyClient.Do(ctx, valkeyClient.B().Get().Key(jwksCacheKey).Build()).AsBytes()
	if err == nil && len(cachedData) > 0 {
		t.Error("Cache should have expired after TTL")
	}

	// Next call should repopulate cache
	_, err = km.GetAllJWKS()
	if err != nil {
		t.Fatalf("Failed to get JWKS after TTL expiry: %v", err)
	}

	// Verify cache is populated again
	cachedData, err = valkeyClient.Do(ctx, valkeyClient.B().Get().Key(jwksCacheKey).Build()).AsBytes()
	if err != nil || len(cachedData) == 0 {
		t.Error("Cache should be repopulated after expiry")
	}
}

// TODO analyze if we need a solution for when a DNS is no more resolvable, as it stays this hangs the app
// until the timeout is reached.
// Test graceful fallback when cache is unavailable
// func TestKeyManager_GetAllJWKS_CacheUnavailable(t *testing.T) {
// 	repo, pgContainer := setupTestPostgres(t)
// 	defer func() {
// 		if err := pgContainer.Terminate(context.Background()); err != nil {
// 			t.Logf("Failed to terminate container: %v", err)
// 		}
// 	}()

// 	valkeyContainer, err := valkey.Run(context.Background(), "valkey/valkey:7.2-alpine")
// 	if err != nil {
// 		t.Fatalf("Failed to start Valkey container: %v", err)
// 	}

// 	// Get client
// 	host, _ := valkeyContainer.Host(context.Background())
// 	port, _ := valkeyContainer.MappedPort(context.Background(), "6379/tcp")
// 	valkeyClient, _ := valkeygo.NewClient(valkeygo.ClientOption{
// 		InitAddress: []string{host + ":" + port.Port()},
// 	})

// 	// Create KeyManager
// 	ctx := context.Background()
// 	km, err := NewKeyManager(ctx, repo, valkeyClient, 10*time.Second)
// 	if err != nil {
// 		t.Fatalf("Failed to create KeyManager: %v", err)
// 	}

// 	// Terminate Valkey container to simulate cache unavailability
// 	if err := valkeyContainer.Terminate(context.Background()); err != nil {
// 		t.Logf("Failed to terminate container: %v", err)
// 	}

// 	// Should still work by falling back to database
// 	jwkSet, err := km.GetAllJWKS()
// 	if err != nil {
// 		t.Fatalf("Should fallback to database when cache unavailable: %v", err)
// 	}

// 	if jwkSet == nil {
// 		t.Fatal("JWKS should not be nil")
// 	}

// 	if jwkSet.Len() < 1 {
// 		t.Error("JWKS should contain at least one key")
// 	}
// }

// Test InvalidateJWKSCache with nil client
func TestKeyManager_InvalidateJWKSCache_NilClient(t *testing.T) {
	t.Parallel()
	repo, pgContainer := setupTestPostgres(t)
	defer func() {
		if err := pgContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()
	km, err := NewKeyManager(ctx, repo, nil, 0)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}

	// Should not error when cache client is nil
	err = km.InvalidateJWKSCache(ctx)
	if err != nil {
		t.Errorf("InvalidateJWKSCache should not error with nil client: %v", err)
	}
}
