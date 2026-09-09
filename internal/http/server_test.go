// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

//go:generate mockgen -build_flags=--mod=mod -package httpserver -destination ./mock_interfaces.go -source=./interfaces.go
//go:generate mockgen -build_flags=--mod=mod -package httpserver -destination ./mock_store.go -source=../session/store.go

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// TestIsValidReturnTo tests the return_to URL validation
func TestIsValidReturnTo(t *testing.T) {
	tests := []struct {
		name     string
		returnTo string
		reqHost  string
		expected bool
	}{
		// Valid relative paths
		{
			name:     "valid relative path root",
			returnTo: "/",
			reqHost:  "localhost:8080",
			expected: true,
		},
		{
			name:     "valid relative path dashboard",
			returnTo: "/dashboard",
			reqHost:  "localhost:8080",
			expected: true,
		},
		{
			name:     "valid relative path with query and fragment",
			returnTo: "/path?a=1&b=2#section",
			reqHost:  "localhost:8080",
			expected: true,
		},
		{
			name:     "valid empty string defaults to root",
			returnTo: "",
			reqHost:  "localhost:8080",
			expected: true,
		},

		// Valid same-host absolute URLs
		{
			name:     "valid same-host absolute http URL",
			returnTo: "http://localhost:8080/dashboard",
			reqHost:  "localhost:8080",
			expected: true,
		},
		{
			name:     "valid same-host absolute https URL",
			returnTo: "https://example.com/login",
			reqHost:  "example.com",
			expected: true,
		},
		{
			name:     "valid same-host absolute URL case-insensitive host",
			returnTo: "https://EXAMPLE.COM/login",
			reqHost:  "example.com",
			expected: true,
		},

		// Invalid external URLs
		{
			name:     "invalid external https URL",
			returnTo: "https://evil.com",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid external http URL with path",
			returnTo: "http://evil.com/dashboard",
			reqHost:  "localhost:8080",
			expected: false,
		},
		{
			name:     "invalid subdomain spoofing",
			returnTo: "https://example.com.evil.com/dashboard",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid different port",
			returnTo: "http://localhost:9090/dashboard",
			reqHost:  "localhost:8080",
			expected: false,
		},

		// Invalid protocol-relative URLs
		{
			name:     "invalid protocol-relative url double slash",
			returnTo: "//evil.com",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid protocol-relative url triple slash",
			returnTo: "///evil.com",
			reqHost:  "example.com",
			expected: false,
		},

		// Invalid backslash evasions
		{
			name:     "invalid backslash evasion slash backslash",
			returnTo: "/\\evil.com",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid backslash evasion double backslash",
			returnTo: "\\\\evil.com",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid backslash evasion single backslash",
			returnTo: "\\evil.com",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid backslash evasion slash double backslash",
			returnTo: "/\\\\evil.com",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid backslash in path",
			returnTo: "/dashboard\\evil.com",
			reqHost:  "example.com",
			expected: false,
		},

		// Invalid unsafe schemes
		{
			name:     "invalid javascript scheme",
			returnTo: "javascript:alert(1)",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid data scheme",
			returnTo: "data:text/html,test",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid vbscript scheme",
			returnTo: "vbscript:msgbox",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid file scheme",
			returnTo: "file:///etc/passwd",
			reqHost:  "example.com",
			expected: false,
		},

		// CRLF injection attempts
		{
			name:     "invalid CRLF injection with Location header",
			returnTo: "/dash\r\nLocation: evil.com",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid newline injection with Set-Cookie header",
			returnTo: "/dash\nSet-Cookie: foo=bar",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid null byte injection",
			returnTo: "/dash\x00/evil",
			reqHost:  "example.com",
			expected: false,
		},

		// Invalid malformed URLs
		{
			name:     "invalid missing scheme colon slash slash",
			returnTo: "://bad",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid malformed IPv6 host",
			returnTo: "http://[::1",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid relative path missing leading slash",
			returnTo: "dashboard",
			reqHost:  "example.com",
			expected: false,
		},
		{
			name:     "invalid URL with spaces",
			returnTo: "http:// evil.com",
			reqHost:  "example.com",
			expected: false,
		},
	}

	server := NewServer(nil, nil, nil, nil, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := server.isValidReturnTo(tt.returnTo, tt.reqHost)
			if got != tt.expected {
				t.Errorf("isValidReturnTo(%q, %q) = %v; expected %v", tt.returnTo, tt.reqHost, got, tt.expected)
			}
		})
	}

	t.Run("Allowed return_to hosts", func(t *testing.T) {
		s := NewServer(nil, nil, nil, nil, nil, WithAllowedHosts([]string{"allowed1.example.com", "allowed2.example.com"}))

		if !s.isValidReturnTo("https://allowed1.example.com/app", "other.example.com") {
			t.Error("expected allowed1.example.com to be valid")
		}
		if !s.isValidReturnTo("http://allowed2.example.com:8080/path", "other.example.com") {
			t.Error("expected allowed2.example.com:8080 to be valid")
		}
		if s.isValidReturnTo("https://not-allowed.example.com/app", "other.example.com") {
			t.Error("expected not-allowed.example.com to be invalid")
		}
	})
}

// TestHandleLogin tests the login handler
func TestHandleLogin(t *testing.T) {
	t.Run("Valid return_to -> 302 to IdP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		oidcProvider := NewMockOIDCProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, oidcProvider, nil)

		cookieManager.EXPECT().
			SetOIDCState(gomock.Any(), gomock.Any(), "/dashboard").
			Return("mock-state-123", nil)

		cookieManager.EXPECT().
			SetOIDCNonce(gomock.Any(), gomock.Any()).
			Return("mock-nonce-456", nil)

		oidcProvider.EXPECT().
			AuthCodeURL("mock-state-123", gomock.Any()).
			Return("https://idp.example.com/auth?state=mock-state-123")

		req := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/dashboard", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got %d", w.Code)
		}
		location := w.Header().Get("Location")
		expectedLocation := "https://idp.example.com/auth?state=mock-state-123"
		if location != expectedLocation {
			t.Errorf("Expected redirect to %s, got %s", expectedLocation, location)
		}
	})

	t.Run("Valid same-origin return_to -> 302 to IdP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		oidcProvider := NewMockOIDCProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, oidcProvider, nil)

		cookieManager.EXPECT().
			SetOIDCState(gomock.Any(), gomock.Any(), "http://localhost:8080/dashboard").
			Return("mock-state-123", nil)

		cookieManager.EXPECT().
			SetOIDCNonce(gomock.Any(), gomock.Any()).
			Return("mock-nonce-456", nil)

		oidcProvider.EXPECT().
			AuthCodeURL("mock-state-123", gomock.Any()).
			Return("https://idp.example.com/auth?state=mock-state-123")

		req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/auth/login?return_to=http://localhost:8080/dashboard", nil)
		req.Host = "localhost:8080"
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got %d", w.Code)
		}
		location := w.Header().Get("Location")
		expectedLocation := "https://idp.example.com/auth?state=mock-state-123"
		if location != expectedLocation {
			t.Errorf("Expected redirect to %s, got %s", expectedLocation, location)
		}
	})

	t.Run("Valid allowed-host return_to -> 302 to IdP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		oidcProvider := NewMockOIDCProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, oidcProvider, nil, WithAllowedHosts([]string{"allowed.example.com"}))

		cookieManager.EXPECT().
			SetOIDCState(gomock.Any(), gomock.Any(), "https://allowed.example.com/app").
			Return("mock-state-123", nil)

		cookieManager.EXPECT().
			SetOIDCNonce(gomock.Any(), gomock.Any()).
			Return("mock-nonce-456", nil)

		oidcProvider.EXPECT().
			AuthCodeURL("mock-state-123", gomock.Any()).
			Return("https://idp.example.com/auth?state=mock-state-123")

		req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/auth/login?return_to=https://allowed.example.com/app", nil)
		req.Host = "localhost:8080"
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got %d", w.Code)
		}
		location := w.Header().Get("Location")
		expectedLocation := "https://idp.example.com/auth?state=mock-state-123"
		if location != expectedLocation {
			t.Errorf("Expected redirect to %s, got %s", expectedLocation, location)
		}
	})

	t.Run("Empty return_to -> defaults to / and 302 to IdP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		oidcProvider := NewMockOIDCProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, oidcProvider, nil)

		cookieManager.EXPECT().
			SetOIDCState(gomock.Any(), gomock.Any(), "/").
			Return("mock-state-123", nil)

		cookieManager.EXPECT().
			SetOIDCNonce(gomock.Any(), gomock.Any()).
			Return("mock-nonce-456", nil)

		oidcProvider.EXPECT().
			AuthCodeURL("mock-state-123", gomock.Any()).
			Return("https://idp.example.com/auth?state=mock-state-123")

		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got %d", w.Code)
		}
	})

	t.Run("Invalid return_to external URL -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		oidcProvider := NewMockOIDCProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, oidcProvider, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=https://evil.com", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Invalid return_to protocol-relative URL -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		oidcProvider := NewMockOIDCProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, oidcProvider, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=//evil.com", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})
}

// setupCallbackSuccessMocks configures mocks for a successful callback flow up to redirect
func setupCallbackSuccessMocks(
	ctrl *gomock.Controller,
	stateData map[string]string,
	reqHost string,
	opts ...ServerOption,
) (*Server, *http.Request, *httptest.ResponseRecorder) {
	cookieManager := NewMockAuthCookieManager(ctrl)
	oidcProvider := NewMockOIDCProvider(ctrl)
	store := NewMockStore(ctrl)
	oauth2Token := NewMockOAuth2Token(ctrl)
	idToken := NewMockIDToken(ctrl)

	server := NewServer(store, nil, cookieManager, oidcProvider, nil, opts...)

	cookieManager.EXPECT().
		GetOIDCState(gomock.Any()).
		Return(stateData, nil)

	cookieManager.EXPECT().
		ClearOIDCState(gomock.Any(), gomock.Any())

	oidcProvider.EXPECT().
		Exchange(gomock.Any(), "mock-code").
		Return(oauth2Token, nil)

	oauth2Token.EXPECT().
		Extra("id_token").
		Return("mock-raw-id-token")

	oidcProvider.EXPECT().
		VerifyIDToken(gomock.Any(), "mock-raw-id-token").
		Return(idToken, nil)

	cookieManager.EXPECT().
		GetOIDCNonce(gomock.Any()).
		Return("mock-nonce-123", nil)

	cookieManager.EXPECT().
		ClearOIDCNonce(gomock.Any(), gomock.Any())

	idToken.EXPECT().
		GetNonce().
		Return("mock-nonce-123", nil)

	idToken.EXPECT().
		Claims(gomock.Any()).
		DoAndReturn(func(v interface{}) error {
			claimsPtr, ok := v.(*struct {
				Email string `json:"email,omitempty"`
			})
			if ok {
				claimsPtr.Email = "user@example.com"
			}
			return nil
		})

	oauth2Token.EXPECT().AccessToken().Return("mock-access-token")
	idToken.EXPECT().GetOriginalToken().Return("mock-id-token")
	oauth2Token.EXPECT().RefreshToken().Return("mock-refresh-token")
	oauth2Token.EXPECT().Expiry().Return(time.Now().Add(1 * time.Hour))

	store.EXPECT().
		Set(gomock.Any(), gomock.Any()).
		Return(nil)

	cookieManager.EXPECT().
		Encode("session_id", gomock.Any()).
		Return("mock-encoded-session", nil)

	reqURL := "/auth/callback?state=mock-state-123&code=mock-code"
	if reqHost != "" {
		reqURL = "http://" + reqHost + reqURL
	}
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	if reqHost != "" {
		req.Host = reqHost
	}
	w := httptest.NewRecorder()

	return server, req, w
}

// TestHandleCallback tests the callback handler
func TestHandleCallback(t *testing.T) {
	t.Run("Valid return_to in state -> 302 redirect to return_to", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		stateData := map[string]string{
			"state":     "mock-state-123",
			"return_to": "/dashboard",
		}
		server, req, w := setupCallbackSuccessMocks(ctrl, stateData, "localhost:8080")

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d", w.Code)
		}
		location := w.Header().Get("Location")
		if location != "/dashboard" {
			t.Errorf("Expected redirect to /dashboard, got %s", location)
		}
	})

	t.Run("Missing return_to in state -> 302 redirect to /", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		stateData := map[string]string{
			"state": "mock-state-123",
		}
		server, req, w := setupCallbackSuccessMocks(ctrl, stateData, "localhost:8080")

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d", w.Code)
		}
		location := w.Header().Get("Location")
		if location != "/" {
			t.Errorf("Expected redirect to /, got %s", location)
		}
	})

	t.Run("Same-origin return_to in state -> 302 redirect to return_to", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		stateData := map[string]string{
			"state":     "mock-state-123",
			"return_to": "http://localhost:8080/dashboard",
		}
		server, req, w := setupCallbackSuccessMocks(ctrl, stateData, "localhost:8080")

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d", w.Code)
		}
		location := w.Header().Get("Location")
		if location != "http://localhost:8080/dashboard" {
			t.Errorf("Expected redirect to http://localhost:8080/dashboard, got %s", location)
		}
	})

	t.Run("Allowed-host return_to in state -> 302 redirect to return_to", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		stateData := map[string]string{
			"state":     "mock-state-123",
			"return_to": "https://allowed.example.com/app",
		}
		server, req, w := setupCallbackSuccessMocks(ctrl, stateData, "localhost:8080", WithAllowedHosts([]string{"allowed.example.com"}))

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d", w.Code)
		}
		location := w.Header().Get("Location")
		if location != "https://allowed.example.com/app" {
			t.Errorf("Expected redirect to https://allowed.example.com/app, got %s", location)
		}
	})

	t.Run("Invalid return_to in state -> fallback to / and 302 redirect", func(t *testing.T) {
		invalidTargets := []string{
			"https://evil.com",
			"//evil.com",
			"javascript:alert(1)",
		}

		for _, target := range invalidTargets {
			t.Run(target, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()

				stateData := map[string]string{
					"state":     "mock-state-123",
					"return_to": target,
				}
				server, req, w := setupCallbackSuccessMocks(ctrl, stateData, "localhost:8080")

				server.Router().ServeHTTP(w, req)

				if w.Code != http.StatusFound {
					t.Errorf("Expected status 302 for return_to %q, got %d", target, w.Code)
				}
				location := w.Header().Get("Location")
				if location != "/" {
					t.Errorf("Expected redirect to /, got %s", location)
				}
			})
		}
	})

	t.Run("State mismatch -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		server := NewServer(nil, nil, cookieManager, nil, nil)

		cookieManager.EXPECT().
			GetOIDCState(gomock.Any()).
			Return(map[string]string{"state": "expected-state"}, nil)

		cookieManager.EXPECT().
			ClearOIDCState(gomock.Any(), gomock.Any())

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=wrong-state&code=mock-code", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "State mismatch") {
			t.Errorf("Expected 'State mismatch', got %s", w.Body.String())
		}
	})

	t.Run("Invalid nonce -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		oidcProvider := NewMockOIDCProvider(ctrl)
		oauth2Token := NewMockOAuth2Token(ctrl)
		idToken := NewMockIDToken(ctrl)

		server := NewServer(nil, nil, cookieManager, oidcProvider, nil)

		cookieManager.EXPECT().
			GetOIDCState(gomock.Any()).
			Return(map[string]string{"state": "mock-state"}, nil)

		cookieManager.EXPECT().
			ClearOIDCState(gomock.Any(), gomock.Any())

		oidcProvider.EXPECT().
			Exchange(gomock.Any(), "mock-code").
			Return(oauth2Token, nil)

		oauth2Token.EXPECT().
			Extra("id_token").
			Return("mock-raw-id-token")

		oidcProvider.EXPECT().
			VerifyIDToken(gomock.Any(), "mock-raw-id-token").
			Return(idToken, nil)

		cookieManager.EXPECT().
			GetOIDCNonce(gomock.Any()).
			Return("mock-nonce-stored", nil)

		cookieManager.EXPECT().
			ClearOIDCNonce(gomock.Any(), gomock.Any())

		idToken.EXPECT().
			GetNonce().
			Return("mock-nonce-different", nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=mock-state&code=mock-code", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Nonce mismatch") {
			t.Errorf("Expected 'Nonce mismatch', got %s", w.Body.String())
		}
	})

	t.Run("Missing code -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		server := NewServer(nil, nil, cookieManager, nil, nil)

		cookieManager.EXPECT().
			GetOIDCState(gomock.Any()).
			Return(map[string]string{"state": "mock-state"}, nil)

		cookieManager.EXPECT().
			ClearOIDCState(gomock.Any(), gomock.Any())

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=mock-state", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Missing code") {
			t.Errorf("Expected 'Missing code', got %s", w.Body.String())
		}
	})
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
