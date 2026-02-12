// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package httpserver

//go:generate mockgen -build_flags=--mod=mod -package httpserver -destination ./mock_interfaces.go -source=./interfaces.go
//go:generate mockgen -build_flags=--mod=mod -package httpserver -destination ./mock_store.go -source=../session/store.go

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"go.uber.org/mock/gomock"
)

// TestHandleJWKS tests the JWKS endpoint
func TestHandleJWKS(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keyManager := NewMockKeyManager(ctrl)
	server := NewServer(nil, keyManager, nil, nil, nil)

	// Create a mock JWK set
	mockSet := jwk.NewSet()
	// Add a mock key to the set (empty set is fine for this test)

	// Setup mock expectations
	keyManager.EXPECT().
		GetAllJWKS().
		Return(mockSet, nil)

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	// Execute request through router
	router := server.Router()
	router.ServeHTTP(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	// Verify response is valid JSON
	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Errorf("Failed to decode JSON response: %v", err)
	}
}

// TestHandleLogin tests the login handler
func TestHandleLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cookieManager := NewMockAuthCookieManager(ctrl)
	oidcProvider := NewMockOIDCProvider(ctrl)

	server := NewServer(nil, nil, cookieManager, oidcProvider, nil)

	// Setup mock expectations
	cookieManager.EXPECT().
		SetOIDCState(gomock.Any(), gomock.Any(), "/dashboard").
		Return("mock-state-123", nil)

	cookieManager.EXPECT().
		SetOIDCNonce(gomock.Any(), gomock.Any()).
		Return("mock-nonce-456", nil)

	oidcProvider.EXPECT().
		AuthCodeURL("mock-state-123", gomock.Any()).
		Return("https://idp.example.com/auth?state=mock-state-123")

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/dashboard", nil)
	w := httptest.NewRecorder()

	// Execute request through router
	router := server.Router()
	router.ServeHTTP(w, req)

	// Verify redirect
	if w.Code != http.StatusFound {
		t.Errorf("Expected status 302 (redirect), got %d", w.Code)
	}

	// Verify redirect location
	location := w.Header().Get("Location")
	expectedLocation := "https://idp.example.com/auth?state=mock-state-123"
	if location != expectedLocation {
		t.Errorf("Expected redirect to %s, got %s", expectedLocation, location)
	}
}

// TestHandleLogout tests the logout handler
func TestHandleLogout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cookieManager := NewMockAuthCookieManager(ctrl)
	store := NewMockStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)
	provider := NewMockOIDCProvider(ctrl)

	server := NewServer(store, keyManager, cookieManager, provider, nil)

	// Setup mock - Decode will fail (no valid cookie), which is OK
	// The handler will still clear the cookie even if decode fails
	cookieManager.EXPECT().
		Decode("session_id", "test-session-value").
		Return("test-session-id", nil).
		AnyTimes() // May or may not be called depending on cookie presence

	// Expect the store Delete to be called
	store.EXPECT().
		Delete(gomock.Any(), "test-session-id").
		Return(nil).
		AnyTimes()

	// Create test request with a cookie
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: "test-session-value",
	})
	w := httptest.NewRecorder()

	// Execute request through router
	router := server.Router()
	router.ServeHTTP(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify response body
	body := w.Body.String()
	if body != "Logged out" {
		t.Errorf("Expected 'Logged out', got %s", body)
	}

	// Verify cookie is cleared
	cookies := w.Result().Cookies()
	foundClearedCookie := false
	for _, cookie := range cookies {
		if cookie.Name == "session_id" && cookie.Value == "" {
			foundClearedCookie = true
			break
		}
	}
	if !foundClearedCookie {
		t.Error("Expected session_id cookie to be cleared")
	}
}

// TestHandleSessions tests the sessions endpoint
func TestHandleSessions(t *testing.T) {
	server := NewServer(nil, nil, nil, nil, nil)

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	w := httptest.NewRecorder()

	// Execute request through router
	router := server.Router()
	router.ServeHTTP(w, req)

	// Verify response - endpoint is not implemented yet
	if w.Code != http.StatusNotImplemented {
		t.Errorf("Expected status 501 (Not Implemented), got %d", w.Code)
	}
}

// TestNewServerWithObservability tests server creation
func TestNewServerWithObservability(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keyManager := NewMockKeyManager(ctrl)

	server := NewServer(nil, keyManager, nil, nil, nil)

	if server == nil {
		t.Error("Expected server to be created")
	}

	// Verify router is created
	router := server.Router()
	if router == nil {
		t.Error("Expected router to be created")
	}
}
