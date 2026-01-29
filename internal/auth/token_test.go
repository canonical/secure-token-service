// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package auth

import (
	"crypto/rsa"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestKeyManager_GenerateKeys(t *testing.T) {
	// Use temp files for testing
	privateKeyPath := "/tmp/test_private.pem"
	publicKeyPath := "/tmp/test_public.pem"
	defer os.Remove(privateKeyPath)
	defer os.Remove(publicKeyPath)

	km, err := NewKeyManager(privateKeyPath, publicKeyPath)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	if km.privateKey == nil {
		t.Error("Private key is nil")
	}

	if km.publicKey == nil {
		t.Error("Public key is nil")
	}

	// Check files were created
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		t.Error("Private key file was not created")
	}

	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		t.Error("Public key file was not created")
	}
}

func TestKeyManager_LoadKeys(t *testing.T) {
	// Generate keys first
	privateKeyPath := "/tmp/test_load_private.pem"
	publicKeyPath := "/tmp/test_load_public.pem"
	defer os.Remove(privateKeyPath)
	defer os.Remove(publicKeyPath)

	km1, err := NewKeyManager(privateKeyPath, publicKeyPath)
	if err != nil {
		t.Fatalf("Failed to create first key manager: %v", err)
	}

	// Load the same keys
	km2, err := NewKeyManager(privateKeyPath, publicKeyPath)
	if err != nil {
		t.Fatalf("Failed to load keys: %v", err)
	}

	if km1.publicKey.N.Cmp(km2.publicKey.N) != 0 {
		t.Error("Loaded public key does not match generated key")
	}
}

func TestKeyManager_MintToken(t *testing.T) {
	privateKeyPath := "/tmp/test_mint_private.pem"
	publicKeyPath := "/tmp/test_mint_public.pem"
	defer os.Remove(privateKeyPath)
	defer os.Remove(publicKeyPath)

	km, err := NewKeyManager(privateKeyPath, publicKeyPath)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	claims := map[string]interface{}{
		"email": "test@example.com",
		"role":  "admin",
	}

	token, err := km.MintToken("user123", "session-service", "internal-services", 3600, claims)
	if err != nil {
		t.Fatalf("Failed to mint token: %v", err)
	}

	if token == "" {
		t.Error("Token is empty")
	}

	// Verify the token
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return km.publicKey, nil
	})

	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	if !parsedToken.Valid {
		t.Error("Token is not valid")
	}

	mapClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Claims are not MapClaims")
	}

	if mapClaims["sub"] != "user123" {
		t.Errorf("Subject mismatch: got %v, want user123", mapClaims["sub"])
	}

	if mapClaims["iss"] != "session-service" {
		t.Errorf("Issuer mismatch: got %v, want session-service", mapClaims["iss"])
	}

	if mapClaims["email"] != "test@example.com" {
		t.Errorf("Email mismatch: got %v, want test@example.com", mapClaims["email"])
	}
}

func TestKeyManager_TokenExpiry(t *testing.T) {
	privateKeyPath := "/tmp/test_expiry_private.pem"
	publicKeyPath := "/tmp/test_expiry_public.pem"
	defer os.Remove(privateKeyPath)
	defer os.Remove(publicKeyPath)

	km, err := NewKeyManager(privateKeyPath, publicKeyPath)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	// Mint token with 1 second expiry
	token, err := km.MintToken("user123", "session-service", "internal-services", 1, nil)
	if err != nil {
		t.Fatalf("Failed to mint token: %v", err)
	}

	// Token should be valid immediately
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return km.publicKey, nil
	})

	if err != nil || !parsedToken.Valid {
		t.Error("Token should be valid immediately after creation")
	}

	// Wait for expiry
	time.Sleep(2 * time.Second)

	// Token should now be expired
	parsedToken, err = jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return km.publicKey, nil
	})

	if err == nil && parsedToken.Valid {
		t.Error("Token should be expired after 2 seconds")
	}
}

func TestKeyManager_GetPublicKey(t *testing.T) {
	privateKeyPath := "/tmp/test_getpub_private.pem"
	publicKeyPath := "/tmp/test_getpub_public.pem"
	defer os.Remove(privateKeyPath)
	defer os.Remove(publicKeyPath)

	km, err := NewKeyManager(privateKeyPath, publicKeyPath)
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}

	pubKey := km.GetPublicKey()
	if pubKey == nil {
		t.Error("GetPublicKey returned nil")
	}

	if _, ok := interface{}(pubKey).(*rsa.PublicKey); !ok {
		t.Error("GetPublicKey did not return an RSA public key")
	}
}
