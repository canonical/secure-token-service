// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package cookie_test

import (
	"testing"

	"github.com/canonical/secure-token-service/internal/cookie"
	"github.com/gorilla/securecookie"
)

func TestCookieManager_EncodeDecode(t *testing.T) {
	hashKey := securecookie.GenerateRandomKey(64)
	blockKey := securecookie.GenerateRandomKey(32)

	cm := cookie.NewCookieManager(hashKey, blockKey)

	name := "session_id"
	value := "test-session-value-123"

	// Test Encode
	encoded, err := cm.Encode(name, value)
	if err != nil {
		t.Fatalf("Failed to encode cookie: %v", err)
	}

	if encoded == "" {
		t.Error("Encoded cookie is empty")
	}

	// Test Decode
	decoded, err := cm.Decode(name, encoded)
	if err != nil {
		t.Fatalf("Failed to decode cookie: %v", err)
	}

	if decoded != value {
		t.Errorf("Decoded value mismatch: got %q, want %q", decoded, value)
	}
}

func TestCookieManager_DecodeInvalid(t *testing.T) {
	hashKey := securecookie.GenerateRandomKey(64)
	blockKey := securecookie.GenerateRandomKey(32)

	cm := cookie.NewCookieManager(hashKey, blockKey)

	// Test decoding invalid value
	_, err := cm.Decode("session_id", "invalid-cookie-value")
	if err == nil {
		t.Error("Expected error when decoding invalid cookie, got nil")
	}
}

func TestCookieManager_WrongKey(t *testing.T) {
	hashKey1 := securecookie.GenerateRandomKey(64)
	blockKey1 := securecookie.GenerateRandomKey(32)
	cm1 := cookie.NewCookieManager(hashKey1, blockKey1)

	hashKey2 := securecookie.GenerateRandomKey(64)
	blockKey2 := securecookie.GenerateRandomKey(32)
	cm2 := cookie.NewCookieManager(hashKey2, blockKey2)

	name := "session_id"
	value := "secret-data"

	// Encode with first manager
	encoded, err := cm1.Encode(name, value)
	if err != nil {
		t.Fatalf("Failed to encode with cm1: %v", err)
	}

	// Try to decode with second manager (different keys)
	_, err = cm2.Decode(name, encoded)
	if err == nil {
		t.Error("Expected error when decoding with different keys, got nil")
	}
}

func TestCookieManager_NoEncryption(t *testing.T) {
	hashKey := securecookie.GenerateRandomKey(64)
	// No block key (no encryption, only signing)
	cm := cookie.NewCookieManager(hashKey, nil)

	name := "public_data"
	value := "visible-but-signed"

	encoded, err := cm.Encode(name, value)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	// Decode should still work
	decoded, err := cm.Decode(name, encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if decoded != value {
		t.Errorf("Decoded value mismatch: got %q, want %q", decoded, value)
	}
}
