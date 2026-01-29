// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/canonical/secure-token-service/internal/auth"
)

func TestHandleJWKS(t *testing.T) {
	// Create a key manager for testing
	km, err := auth.NewKeyManager("./test_private.pem", "./test_public.pem")
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}
	defer func() {
		// Clean up test keys
		// os.Remove("./test_private.pem")
		// os.Remove("./test_public.pem")
	}()

	// Create server with nil session store (not needed for JWKS endpoint)
	server := NewServer(nil, km)

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	// Call the handler
	server.handleJWKS(w, req)

	// Check response status
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	// Parse the response
	var jwks map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatalf("Failed to decode JWKS response: %v", err)
	}

	// Verify JWKS structure
	keys, ok := jwks["keys"].([]interface{})
	if !ok {
		t.Fatal("JWKS response missing 'keys' array")
	}

	if len(keys) != 1 {
		t.Fatalf("Expected 1 key, got %d", len(keys))
	}

	// Verify key properties
	key := keys[0].(map[string]interface{})

	expectedFields := []string{"kty", "use", "alg", "kid", "n", "e"}
	for _, field := range expectedFields {
		if _, ok := key[field]; !ok {
			t.Errorf("Key missing required field: %s", field)
		}
	}

	// Verify specific values
	if key["kty"] != "RSA" {
		t.Errorf("Expected kty=RSA, got %v", key["kty"])
	}
	if key["use"] != "sig" {
		t.Errorf("Expected use=sig, got %v", key["use"])
	}
	if key["alg"] != "RS256" {
		t.Errorf("Expected alg=RS256, got %v", key["alg"])
	}
	if key["kid"] != "janus-key-1" {
		t.Errorf("Expected kid=janus-key-1, got %v", key["kid"])
	}

	t.Logf("JWKS Response: %+v", jwks)
}
