// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package cookie_test

import (
	"testing"

	"github.com/canonical/secure-token-service/internal/cookie"
	"github.com/chmike/securecookie"
)

func TestCookieManager_EncodeDecode(t *testing.T) {
	key := securecookie.MustGenerateRandomKey()

	cm := cookie.NewCookieManager(key)

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
	key := securecookie.MustGenerateRandomKey()

	cm := cookie.NewCookieManager(key)

	// Test decoding invalid value
	_, err := cm.Decode("session_id", "invalid-cookie-value")
	if err == nil {
		t.Error("Expected error when decoding invalid cookie, got nil")
	}
}

func TestCookieManager_WrongKey(t *testing.T) {
	key1 := securecookie.MustGenerateRandomKey()
	cm1 := cookie.NewCookieManager(key1)

	key2 := securecookie.MustGenerateRandomKey()
	cm2 := cookie.NewCookieManager(key2)

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

func TestCookieManager_ShortKey(t *testing.T) {
	// Test with a short key (should be padded to 32 bytes)
	key := []byte("short-key")

	cm := cookie.NewCookieManager(key)

	name := "session_id"
	value := "test-value"

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
