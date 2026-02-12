// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/canonical/secure-token-service/internal/auth"
	"github.com/canonical/secure-token-service/internal/config"
	"github.com/canonical/secure-token-service/internal/db"
	"github.com/canonical/secure-token-service/internal/session"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	// rotateKeyCmd represents the rotate-key command
	rotateKeyCmd = &cobra.Command{
		Use:   "rotate-key",
		Short: "Rotate the JWKS signing key",
		Long: `Rotate the JWKS signing key by generating a new key and moving the current active key to retired status.
		
The new key will be used for signing JWTs, while the old key(s) will remain available 
for verification via the JWKS endpoint during the rotation period.`,
		RunE: runRotateKey,
	}
)

func init() {
	rootCmd.AddCommand(rotateKeyCmd)
}

// runRotateKey executes the key rotation logic
func runRotateKey(cmd *cobra.Command, args []string) error {
	log.Println("Starting JWKS key rotation...")

	ctx := context.Background()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	log.Printf("Configuration loaded, connecting to database: %s", cfg.DatabaseURL)

	// Initialize Database
	database, err := db.NewDB(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()
	log.Println("Database connected")

	// Initialize JWKS Repository
	jwksRepo := db.NewPostgresJWKSRepository(database.Pool())

	// Get current active key info for logging
	currentKey, err := jwksRepo.GetLatestActiveKey(ctx)
	if err != nil {
		log.Printf("Warning: No current active key found: %v", err)
	} else {
		log.Printf("Current active key: %s (created at %s)", currentKey.KID, currentKey.CreatedAt.Format(time.RFC3339))
	}

	// Generate new RSA key pair
	log.Println("Generating new RSA key pair (2048-bit)...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Marshal private key to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Marshal public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Create new key ID
	kid := "janus-key-" + uuid.New().String()[:8]
	log.Printf("Generated new key with ID: %s", kid)

	// Store complete key data as JSONB
	keyData := map[string]interface{}{
		"kty":         "RSA",
		"kid":         kid,
		"use":         "sig",
		"alg":         "RS256",
		"private_pem": string(privateKeyPEM),
		"public_pem":  string(publicKeyPEM),
	}

	keyDataJSON, err := json.Marshal(keyData)
	if err != nil {
		return fmt.Errorf("failed to marshal key data: %w", err)
	}

	// Create new key entry
	newKey := &db.JWKSKey{
		SID:       "public",
		KID:       kid,
		Version:   0,
		KeyData:   keyDataJSON,
		CreatedAt: time.Now(),
	}

	// Perform rotation (atomic transaction: retire old key(s), insert new key)
	log.Println("Performing key rotation (this is an atomic operation)...")
	if err := jwksRepo.RotateKey(ctx, newKey); err != nil {
		return fmt.Errorf("failed to rotate key: %w", err)
	}

	log.Println("✓ Key rotation completed successfully!")
	log.Printf("✓ New active key: %s", kid)
	if currentKey != nil {
		log.Printf("✓ Previous key %s moved to retired set (still available for verification)", currentKey.KID)
	}
	log.Println("✓ JWKS endpoint will now return both active and retired keys")

	// Verify rotation
	verifyKey, err := jwksRepo.GetLatestActiveKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to verify rotation: %w", err)
	}

	if verifyKey.KID != kid {
		return fmt.Errorf("rotation verification failed: expected kid %s, got %s", kid, verifyKey.KID)
	}

	log.Println("✓ Rotation verified: new key is active")

	// Invalidate JWKS cache after rotation
	// Initialize Valkey client for cache invalidation
	valkeyClient, err := session.NewValkeyClient(cfg.CacheAddr, cfg.CachePassword, cfg.CacheDB)
	if err != nil {
		log.Printf("Warning: Failed to connect to cache for invalidation: %v", err)
		log.Println("  Cached JWKS may be stale until TTL expires")
	} else {
		// Invalidate cache
		cacheTTL := time.Duration(cfg.JWKSCacheTTL) * time.Second
		// Create temporary KeyManager just for cache invalidation
		tempKeyManager, _ := auth.NewKeyManager(ctx, jwksRepo, valkeyClient, cacheTTL)
		if err := tempKeyManager.InvalidateJWKSCache(ctx); err != nil {
			log.Printf("Warning: Failed to invalidate JWKS cache: %v", err)
			log.Println("  Cached JWKS may be stale until TTL expires")
		} else {
			log.Println("✓ JWKS cache invalidated successfully")
		}
	}

	return nil
}
