// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// KeyManager handles RSA key generation and JWT signing.
type KeyManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewKeyManager creates a new KeyManager and loads/generates RSA keys.
func NewKeyManager(privateKeyPath, publicKeyPath string) (*KeyManager, error) {
	km := &KeyManager{}

	// Try to load existing keys
	if err := km.loadKeys(privateKeyPath, publicKeyPath); err != nil {
		// Generate new keys if loading fails
		if err := km.generateKeys(privateKeyPath, publicKeyPath); err != nil {
			return nil, fmt.Errorf("failed to generate keys: %w", err)
		}
	}

	return km, nil
}

// loadKeys loads RSA keys from disk.
func (km *KeyManager) loadKeys(privateKeyPath, publicKeyPath string) error {
	// Load private key
	privateKeyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey

	return nil
}

// generateKeys generates new RSA keys and saves them to disk.
func (km *KeyManager) generateKeys(privateKeyPath, publicKeyPath string) error {
	// Generate 2048-bit RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey

	// Ensure directory exists
	os.MkdirAll("./keys", 0755)

	// Save private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Save public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(km.publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// MintToken creates a new internal JWT signed with RS256.
func (km *KeyManager) MintToken(subject, issuer, audience string, expirySeconds int, claims map[string]interface{}) (string, error) {
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
	return token.SignedString(km.privateKey)
}

// GetPublicKey returns the public key for JWKS endpoint.
func (km *KeyManager) GetPublicKey() *rsa.PublicKey {
	return km.publicKey
}

// GetJWK returns the public key as a JWK with proper metadata.
func (km *KeyManager) GetJWK() (jwk.Key, error) {
	key, err := jwk.FromRaw(km.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from public key: %w", err)
	}

	// Set JWK metadata
	if err := key.Set(jwk.KeyIDKey, "janus-key-1"); err != nil {
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
