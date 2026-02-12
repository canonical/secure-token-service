// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/canonical/secure-token-service/internal/db"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/valkey-io/valkey-go"
)

// Cache-related constants
const jwksCacheKey = "jwks:all"

// KeyManager handles RSA key generation and JWT signing with database storage.
type KeyManager struct {
	repo        db.JWKSRepository
	ctx         context.Context
	cacheClient valkey.Client // Valkey client for JWKS caching
	cacheTTL    time.Duration // Cache TTL for JWKS
}

// NewKeyManager creates a new KeyManager that uses database storage and optional Valkey caching.
// If cacheClient is nil or cacheTTL is 0, caching is disabled.
func NewKeyManager(ctx context.Context, repo db.JWKSRepository, cacheClient valkey.Client, cacheTTL time.Duration) (*KeyManager, error) {
	km := &KeyManager{
		repo:        repo,
		ctx:         ctx,
		cacheClient: cacheClient,
		cacheTTL:    cacheTTL,
	}

	// Check if we have an active key, if not generate one
	_, err := repo.GetLatestActiveKey(ctx)
	if err != nil {
		// No active key exists, generate and save initial  key
		if err := km.generateAndSaveKey(); err != nil {
			return nil, fmt.Errorf("failed to generate initial key: %w", err)
		}
	}

	return km, nil
}

// generateAndSaveKey generates a new RSA key pair and saves it to the database.
func (km *KeyManager) generateAndSaveKey() error {
	// Generate 2048-bit RSA key
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

	// Create JWK-style representation with both keys
	kid := "janus-key-" + uuid.New().String()[:8]

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

	// Save to database
	dbKey := &db.JWKSKey{
		SID:       "public",
		KID:       kid,
		Version:   0,
		KeyData:   keyDataJSON,
		CreatedAt: time.Now(),
	}

	if err := km.repo.SaveKey(km.ctx, dbKey); err != nil {
		return fmt.Errorf("failed to save key to database: %w", err)
	}

	return nil
}

// getLatestPrivateKey fetches the latest active key and extracts the private key for signing.
func (km *KeyManager) getLatestPrivateKey() (*rsa.PrivateKey, string, error) {
	dbKey, err := km.repo.GetLatestActiveKey(km.ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get latest active key: %w", err)
	}

	// Parse key data
	var keyData map[string]interface{}
	if err := json.Unmarshal(dbKey.KeyData, &keyData); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal key data: %w", err)
	}

	// Extract private key PEM
	privateKeyPEM, ok := keyData["private_pem"].(string)
	if !ok {
		return nil, "", fmt.Errorf("private_pem not found in key data")
	}

	// Extract KID
	kid, ok := keyData["kid"].(string)
	if !ok {
		return nil, "", fmt.Errorf("kid not found in key data")
	}

	// Decode PEM
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, "", fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, kid, nil
}

// MintToken creates a new internal JWT signed with RS256 using the latest active key.
func (km *KeyManager) MintToken(subject, issuer, audience string, expirySeconds int, claims map[string]interface{}) (string, error) {
	// ALWAYS get the latest key for signing
	privateKey, kid, err := km.getLatestPrivateKey()
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	now := time.Now()

	// Create standard claims
	tokenClaims := jwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Duration(expirySeconds) * time.Second).Unix(),
	}

	// Add custom claims
	for k, v := range claims {
		tokenClaims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	token.Header["kid"] = kid // Set KID in JWT header

	return token.SignedString(privateKey)
}

// GetPublicKey returns the latest active public key.
func (km *KeyManager) GetPublicKey() (*rsa.PublicKey, error) {
	dbKey, err := km.repo.GetLatestActiveKey(km.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest active key: %w", err)
	}

	// Parse key data
	var keyData map[string]interface{}
	if err := json.Unmarshal(dbKey.KeyData, &keyData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key data: %w", err)
	}

	// Extract public key PEM
	publicKeyPEM, ok := keyData["public_pem"].(string)
	if !ok {
		return nil, fmt.Errorf("public_pem not found in key data")
	}

	// Decode PEM
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}

	return rsaPublicKey, nil
}

// GetJWK returns the latest active public key as a JWK with proper metadata.
func (km *KeyManager) GetJWK() (jwk.Key, error) {
	publicKey, err := km.GetPublicKey()
	if err != nil {
		return nil, err
	}

	dbKey, err := km.repo.GetLatestActiveKey(km.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest active key: %w", err)
	}

	// Parse key data for KID
	var keyData map[string]interface{}
	if err := json.Unmarshal(dbKey.KeyData, &keyData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key data: %w", err)
	}

	kid, _ := keyData["kid"].(string)

	key, err := jwk.FromRaw(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from public key: %w", err)
	}

	// Set JWK metadata
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		return nil, fmt.Errorf("failed to set algorithm: %w", err)
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("failed to set key usage: %w", err)
	}

	return key, nil
}

// getAllJWKSFromDB returns all public keys (active + retired) as a JWK Set from the database.
func (km *KeyManager) getAllJWKSFromDB() (jwk.Set, error) {
	dbKeys, err := km.repo.GetAllPublicKeys(km.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get all public keys: %w", err)
	}

	set := jwk.NewSet()

	for _, dbKey := range dbKeys {
		// Parse key data
		var keyData map[string]interface{}
		if err := json.Unmarshal(dbKey.KeyData, &keyData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal key data for %s: %w", dbKey.KID, err)
		}

		// Extract public key PEM
		publicKeyPEM, ok := keyData["public_pem"].(string)
		if !ok {
			continue // Skip keys without public PEM
		}

		// Decode PEM
		block, _ := pem.Decode([]byte(publicKeyPEM))
		if block == nil {
			continue
		}

		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}

		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}

		// Create JWK
		key, err := jwk.FromRaw(rsaPublicKey)
		if err != nil {
			continue
		}

		kid, _ := keyData["kid"].(string)
		key.Set(jwk.KeyIDKey, kid)
		key.Set(jwk.AlgorithmKey, "RS256")
		key.Set(jwk.KeyUsageKey, "sig")

		set.AddKey(key)
	}

	return set, nil
}

// GetAllJWKS returns all public keys with Valkey caching.
// Falls back to database if cache is unavailable or disabled.
func (km *KeyManager) GetAllJWKS() (jwk.Set, error) {
	// If caching is disabled, query database directly
	if km.cacheClient == nil || km.cacheTTL == 0 {
		return km.getAllJWKSFromDB()
	}

	// Try to get from cache
	ctx := km.ctx
	cachedData, err := km.cacheClient.Do(ctx, km.cacheClient.B().Get().Key(jwksCacheKey).Build()).AsBytes()
	if err == nil && len(cachedData) > 0 {
		// Cache hit - deserialize
		set, err := jwk.Parse(cachedData)
		if err == nil {
			return set, nil
		}
		// If deserialization fails, fall through to database query
	}

	// Cache miss - query database
	set, err := km.getAllJWKSFromDB()
	if err != nil {
		return nil, err
	}

	// Serialize and store in cache (best effort - don't fail on cache errors)
	if data, err := json.Marshal(set); err == nil {
		ttlSeconds := int64(km.cacheTTL.Seconds())
		_ = km.cacheClient.Do(ctx, km.cacheClient.B().Setex().Key(jwksCacheKey).Seconds(ttlSeconds).Value(string(data)).Build()).Error()
	}

	return set, nil
}

// InvalidateJWKSCache removes the cached JWKS data.
// Should be called after key rotation.
func (km *KeyManager) InvalidateJWKSCache(ctx context.Context) error {
	if km.cacheClient == nil {
		return nil // No cache to invalidate
	}

	err := km.cacheClient.Do(ctx, km.cacheClient.B().Del().Key(jwksCacheKey).Build()).Error()
	if err != nil {
		return fmt.Errorf("failed to invalidate JWKS cache: %w", err)
	}

	return nil
}
