// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func setupTestPostgres(t *testing.T) (*DB, *PostgresJWKSRepository, *postgres.PostgresContainer) {
	ctx := context.Background()

	// Start PostgreSQL container
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
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
	var db *DB
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		db, err = NewDB(ctx, connStr)
		if err == nil {
			break
		}
		if i < maxRetries-1 {
			time.Sleep(time.Second)
		}
	}
	if err != nil {
		t.Fatalf("Failed to create DB after %d retries: %v", maxRetries, err)
	}

	// Run migrations
	if err := db.RunMigrations(ctx); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	repo := NewPostgresJWKSRepository(db.Pool())

	return db, repo, pgContainer
}

func TestPostgresJWKSRepository_SaveAndGetLatestActiveKey(t *testing.T) {
	db, repo, container := setupTestPostgres(t)
	defer func() {
		db.Close()
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()

	// Create test key
	keyData := json.RawMessage(`{"kty":"RSA","kid":"test-key-1","use":"sig","alg":"RS256","n":"test-n","e":"AQAB"}`)
	key := &JWKSKey{
		SID:       "public",
		KID:       "test-key-1",
		Version:   0,
		KeyData:   keyData,
		CreatedAt: time.Now(),
	}

	// Save key
	err := repo.SaveKey(ctx, key)
	if err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}

	// Get latest active key
	retrieved, err := repo.GetLatestActiveKey(ctx)
	if err != nil {
		t.Fatalf("Failed to get latest active key: %v", err)
	}

	if retrieved.KID != key.KID {
		t.Errorf("KID mismatch: got %v, want %v", retrieved.KID, key.KID)
	}

	if retrieved.SID != "public" {
		t.Errorf("SID mismatch: got %v, want public", retrieved.SID)
	}
}

func TestPostgresJWKSRepository_GetAllPublicKeys(t *testing.T) {
	db, repo, container := setupTestPostgres(t)
	defer func() {
		db.Close()
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()

	// Create active key
	activeKey := &JWKSKey{
		SID:       "public",
		KID:       "active-key",
		Version:   0,
		KeyData:   json.RawMessage(`{"kty":"RSA","kid":"active-key","use":"sig"}`),
		CreatedAt: time.Now(),
	}
	if err := repo.SaveKey(ctx, activeKey); err != nil {
		t.Fatalf("Failed to save active key: %v", err)
	}

	// Create retired key
	retiredKey := &JWKSKey{
		SID:       "public.retired",
		KID:       "retired-key",
		Version:   0,
		KeyData:   json.RawMessage(`{"kty":"RSA","kid":"retired-key","use":"sig"}`),
		CreatedAt: time.Now().Add(-1 * time.Hour),
	}
	if err := repo.SaveKey(ctx, retiredKey); err != nil {
		t.Fatalf("Failed to save retired key: %v", err)
	}

	// Get all public keys
	keys, err := repo.GetAllPublicKeys(ctx)
	if err != nil {
		t.Fatalf("Failed to get all public keys: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(keys))
	}

	// Verify order (most recent first)
	if keys[0].KID != "active-key" {
		t.Errorf("Expected first key to be active-key, got %s", keys[0].KID)
	}
}

func TestPostgresJWKSRepository_RotateKey(t *testing.T) {
	db, repo, container := setupTestPostgres(t)
	defer func() {
		db.Close()
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()

	// Create initial active key
	oldKey := &JWKSKey{
		SID:       "public",
		KID:       "old-key",
		Version:   0,
		KeyData:   json.RawMessage(`{"kty":"RSA","kid":"old-key","use":"sig"}`),
		CreatedAt: time.Now().Add(-1 * time.Hour),
	}
	if err := repo.SaveKey(ctx, oldKey); err != nil {
		t.Fatalf("Failed to save old key: %v", err)
	}

	// Create new key for rotation
	newKey := &JWKSKey{
		SID:       "public",
		KID:       "new-key",
		Version:   0,
		KeyData:   json.RawMessage(`{"kty":"RSA","kid":"new-key","use":"sig"}`),
		CreatedAt: time.Now(),
	}

	// Rotate key
	err := repo.RotateKey(ctx, newKey)
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Verify new key is active
	activeKey, err := repo.GetLatestActiveKey(ctx)
	if err != nil {
		t.Fatalf("Failed to get active key: %v", err)
	}

	if activeKey.KID != "new-key" {
		t.Errorf("Expected active key to be new-key, got %s", activeKey.KID)
	}

	// Verify old key is retired
	allKeys, err := repo.GetAllPublicKeys(ctx)
	if err != nil {
		t.Fatalf("Failed to get all keys: %v", err)
	}

	var retiredKey *JWKSKey
	for _, k := range allKeys {
		if k.KID == "old-key" {
			retiredKey = k
			break
		}
	}

	if retiredKey == nil {
		t.Fatal("Old key not found in all keys")
	}

	if retiredKey.SID != "public.retired" {
		t.Errorf("Expected old key SID to be public.retired, got %s", retiredKey.SID)
	}
}

func TestPostgresJWKSRepository_DeleteKey(t *testing.T) {
	db, repo, container := setupTestPostgres(t)
	defer func() {
		db.Close()
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()

	// Create and save key
	key := &JWKSKey{
		SID:       "public",
		KID:       "delete-me",
		Version:   0,
		KeyData:   json.RawMessage(`{"kty":"RSA","kid":"delete-me","use":"sig"}`),
		CreatedAt: time.Now(),
	}
	if err := repo.SaveKey(ctx, key); err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}

	// Delete key
	err := repo.DeleteKey(ctx, "public", "delete-me")
	if err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	// Verify key is deleted
	_, err = repo.GetKeyByKID(ctx, "delete-me")
	if err == nil {
		t.Error("Expected error when getting deleted key, got nil")
	}
}
