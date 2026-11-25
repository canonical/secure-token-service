// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

//go:generate mockgen -build_flags=--mod=mod -package httpserver -destination ./mock_interfaces.go -source=./interfaces.go
//go:generate mockgen -build_flags=--mod=mod -package httpserver -destination ./mock_store.go -source=../session/store.go

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/canonical/secure-token-service/internal/auth/openid"
	"github.com/canonical/secure-token-service/internal/cookie"
	"github.com/canonical/secure-token-service/internal/observability"
	"github.com/canonical/secure-token-service/internal/session"
	"github.com/lestrrat-go/jwx/v4/jwk"
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
	t.Run("Valid return_to -> 302 to IdP (default OIDC)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		oidcProvider := NewMockOIDCProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, oidcProvider, nil)

		cookieManager.EXPECT().
			SetAuthState(gomock.Any(), gomock.Any(), cookie.AuthState{ReturnTo: "/dashboard", Provider: "oidc"}).
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

	t.Run("Explicit provider=oidc -> 302 to OIDC IdP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		oidcProvider := NewMockOIDCProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, oidcProvider, nil)

		cookieManager.EXPECT().
			SetAuthState(gomock.Any(), gomock.Any(), cookie.AuthState{ReturnTo: "/dashboard", Provider: "oidc"}).
			Return("mock-state-123", nil)

		cookieManager.EXPECT().
			SetOIDCNonce(gomock.Any(), gomock.Any()).
			Return("mock-nonce-456", nil)

		oidcProvider.EXPECT().
			AuthCodeURL("mock-state-123", gomock.Any()).
			Return("https://idp.example.com/auth?state=mock-state-123")

		req := httptest.NewRequest(http.MethodGet, "/auth/login?provider=oidc&return_to=/dashboard", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got %d", w.Code)
		}
	})

	t.Run("Explicit provider=openid -> 302 to OpenID IdP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		openIDProvider := NewMockOpenIDProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, nil, nil, WithOpenIDProvider(openIDProvider))

		cookieManager.EXPECT().
			SetAuthState(gomock.Any(), gomock.Any(), cookie.AuthState{ReturnTo: "/dashboard", Provider: "openid"}).
			Return("mock-openid-state", nil)

		openIDProvider.EXPECT().
			BuildAuthURL("http://localhost:8080/auth/openid/callback", "mock-openid-state").
			Return("https://login.ubuntu.com/+openid?openid.ns=...", nil)

		req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/auth/login?provider=openid&return_to=/dashboard", nil)
		req.Host = "localhost:8080"
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got %d", w.Code)
		}
		location := w.Header().Get("Location")
		if !strings.HasPrefix(location, "https://login.ubuntu.com/+openid") {
			t.Errorf("Expected OpenID redirect location, got %s", location)
		}
	})

	t.Run("OpenID with X-Forwarded-Proto https builds https callback URL", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		openIDProvider := NewMockOpenIDProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, nil, nil, WithOpenIDProvider(openIDProvider))

		cookieManager.EXPECT().
			SetAuthState(gomock.Any(), gomock.Any(), cookie.AuthState{ReturnTo: "/dashboard", Provider: "openid"}).
			Return("mock-openid-state", nil)

		openIDProvider.EXPECT().
			BuildAuthURL("https://example.com/auth/openid/callback", "mock-openid-state").
			Return("https://login.ubuntu.com/+openid?openid.ns=...", nil)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/auth/login?provider=openid&return_to=/dashboard", nil)
		req.Host = "example.com"
		req.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got %d", w.Code)
		}
	})

	t.Run("Default provider configured as openid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		openIDProvider := NewMockOpenIDProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, nil, nil,
			WithOpenIDProvider(openIDProvider),
			WithDefaultAuthProvider("openid"),
		)

		cookieManager.EXPECT().
			SetAuthState(gomock.Any(), gomock.Any(), cookie.AuthState{ReturnTo: "/dashboard", Provider: "openid"}).
			Return("mock-openid-state", nil)

		openIDProvider.EXPECT().
			BuildAuthURL("http://localhost:8080/auth/openid/callback", "mock-openid-state").
			Return("https://login.ubuntu.com/+openid?openid.ns=...", nil)

		// No provider query param -> uses defaultProvider ("openid")
		req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/auth/login?return_to=/dashboard", nil)
		req.Host = "localhost:8080"
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d", w.Code)
		}
	})

	t.Run("OpenID requested but provider not configured -> 500", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		server := NewServer(nil, nil, cookieManager, nil, nil) // no openIDProvider

		req := httptest.NewRequest(http.MethodGet, "/auth/login?provider=openid&return_to=/dashboard", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", w.Code)
		}
	})

	t.Run("OIDC requested but provider not configured -> 500", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		server := NewServer(nil, nil, cookieManager, nil, nil) // no oidcProvider

		req := httptest.NewRequest(http.MethodGet, "/auth/login?provider=oidc&return_to=/dashboard", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", w.Code)
		}
	})

	t.Run("Unsupported provider -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		server := NewServer(nil, nil, cookieManager, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/login?provider=saml&return_to=/dashboard", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Unsupported provider") {
			t.Errorf("Expected 'Unsupported provider', got %s", w.Body.String())
		}
	})

	t.Run("Valid same-origin return_to -> 302 to IdP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		oidcProvider := NewMockOIDCProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, oidcProvider, nil)

		cookieManager.EXPECT().
			SetAuthState(gomock.Any(), gomock.Any(), cookie.AuthState{ReturnTo: "http://localhost:8080/dashboard", Provider: "oidc"}).
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
			SetAuthState(gomock.Any(), gomock.Any(), cookie.AuthState{ReturnTo: "https://allowed.example.com/app", Provider: "oidc"}).
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
			SetAuthState(gomock.Any(), gomock.Any(), cookie.AuthState{ReturnTo: "/", Provider: "oidc"}).
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
	stateData *cookie.AuthState,
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
		GetAuthState(gomock.Any()).
		Return(stateData, nil)

	cookieManager.EXPECT().
		ClearAuthState(gomock.Any(), gomock.Any())

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
			claimsPtr, ok := v.(*map[string]interface{})
			if ok {
				*claimsPtr = map[string]interface{}{
					"email": "user@example.com",
				}
			}
			return nil
		})

	oauth2Token.EXPECT().AccessToken().Return("mock-access-token")
	idToken.EXPECT().GetOriginalToken().Return("mock-id-token")
	oauth2Token.EXPECT().RefreshToken().Return("mock-refresh-token")

	store.EXPECT().
		Set(gomock.Any(), gomock.Any()).
		Return(nil)

	cookieManager.EXPECT().
		SetSessionCookie(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil)

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

// TestHandleCallback_CookieExpiryUsesSessionLifetime checks the cookie outlives a short-lived upstream token.
func TestHandleCallback_CookieExpiryUsesSessionLifetime(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cookieManager := NewMockAuthCookieManager(ctrl)
	oidcProvider := NewMockOIDCProvider(ctrl)
	store := NewMockStore(ctrl)
	oauth2Token := NewMockOAuth2Token(ctrl)
	idToken := NewMockIDToken(ctrl)

	sessionExpiry := 24 * time.Hour
	server := NewServer(store, nil, cookieManager, oidcProvider, nil, WithSessionExpiry(sessionExpiry))

	cookieManager.EXPECT().GetAuthState(gomock.Any()).Return(&cookie.AuthState{State: "mock-state-123", Provider: "oidc"}, nil)
	cookieManager.EXPECT().ClearAuthState(gomock.Any(), gomock.Any())
	oidcProvider.EXPECT().Exchange(gomock.Any(), "mock-code").Return(oauth2Token, nil)
	oauth2Token.EXPECT().Extra("id_token").Return("mock-raw-id-token")
	oidcProvider.EXPECT().VerifyIDToken(gomock.Any(), "mock-raw-id-token").Return(idToken, nil)
	cookieManager.EXPECT().GetOIDCNonce(gomock.Any()).Return("mock-nonce-123", nil)
	cookieManager.EXPECT().ClearOIDCNonce(gomock.Any(), gomock.Any())
	idToken.EXPECT().GetNonce().Return("mock-nonce-123", nil)
	idToken.EXPECT().Claims(gomock.Any()).DoAndReturn(func(v interface{}) error {
		claimsPtr, ok := v.(*map[string]interface{})
		if ok {
			*claimsPtr = map[string]interface{}{
				"email": "user@example.com",
			}
		}
		return nil
	})
	oauth2Token.EXPECT().AccessToken().Return("mock-access-token")
	idToken.EXPECT().GetOriginalToken().Return("mock-id-token")
	oauth2Token.EXPECT().RefreshToken().Return("mock-refresh-token")

	var savedSession *session.Session
	store.EXPECT().Set(gomock.Any(), gomock.Any()).DoAndReturn(func(_ interface{}, s *session.Session, _ ...session.SetOption) error {
		savedSession = s
		return nil
	})

	var cookieExpiry time.Time
	cookieManager.EXPECT().
		SetSessionCookie(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ http.ResponseWriter, _ *http.Request, _ string, expiresAt time.Time) error {
			cookieExpiry = expiresAt
			return nil
		})

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=mock-state-123&code=mock-code", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("Expected status 302, got %d", w.Code)
	}
	if remaining := time.Until(cookieExpiry); remaining < sessionExpiry-time.Minute || remaining > sessionExpiry {
		t.Errorf("Cookie expiry in %v, want about %v", remaining, sessionExpiry)
	}
	if savedSession == nil {
		t.Fatal("Expected session to be saved")
	}
	if remaining := time.Until(savedSession.ExpiresAt); remaining < sessionExpiry-time.Minute || remaining > sessionExpiry {
		t.Errorf("Session ExpiresAt in %v, want about %v", remaining, sessionExpiry)
	}
}

// TestHandleCallback tests the callback handler
func TestHandleCallback(t *testing.T) {
	t.Run("Valid return_to in state -> 302 redirect to return_to", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		stateData := &cookie.AuthState{
			State:    "mock-state-123",
			ReturnTo: "/dashboard",
			Provider: "oidc",
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

		stateData := &cookie.AuthState{
			State:    "mock-state-123",
			Provider: "oidc",
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

		stateData := &cookie.AuthState{
			State:    "mock-state-123",
			ReturnTo: "http://localhost:8080/dashboard",
			Provider: "oidc",
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

		stateData := &cookie.AuthState{
			State:    "mock-state-123",
			ReturnTo: "https://allowed.example.com/app",
			Provider: "oidc",
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

				stateData := &cookie.AuthState{
					State:    "mock-state-123",
					ReturnTo: target,
					Provider: "oidc",
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
			GetAuthState(gomock.Any()).
			Return(&cookie.AuthState{State: "expected-state", Provider: "oidc"}, nil)

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

	t.Run("Provider mismatch -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		server := NewServer(nil, nil, cookieManager, nil, nil)

		cookieManager.EXPECT().
			GetAuthState(gomock.Any()).
			Return(&cookie.AuthState{State: "mock-state", Provider: "openid"}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=mock-state&code=mock-code", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Provider mismatch") {
			t.Errorf("Expected 'Provider mismatch', got %s", w.Body.String())
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
			GetAuthState(gomock.Any()).
			Return(&cookie.AuthState{State: "mock-state", Provider: "oidc"}, nil)

		cookieManager.EXPECT().
			ClearAuthState(gomock.Any(), gomock.Any())

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
			GetAuthState(gomock.Any()).
			Return(&cookie.AuthState{State: "mock-state", Provider: "oidc"}, nil)

		cookieManager.EXPECT().
			ClearAuthState(gomock.Any(), gomock.Any())

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

// TestHandleOpenIDCallback tests the OpenID callback handler
func TestHandleOpenIDCallback(t *testing.T) {
	t.Run("Valid OpenID callback -> 302 redirect to return_to", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		openIDProvider := NewMockOpenIDProvider(ctrl)
		store := NewMockStore(ctrl)

		server := NewServer(store, nil, cookieManager, nil, nil, WithOpenIDProvider(openIDProvider))

		cookieManager.EXPECT().
			GetAuthState(gomock.Any()).
			Return(&cookie.AuthState{State: "mock-openid-state", ReturnTo: "/dashboard", Provider: "openid"}, nil)

		cookieManager.EXPECT().
			ClearAuthState(gomock.Any(), gomock.Any())

		mockClaims := &openid.Claims{
			ClaimedID: "https://login.ubuntu.com/+id/user123",
			Email:     "testuser@example.com",
			FullName:  "Test User",
			Nickname:  "testuser",
		}

		openIDProvider.EXPECT().
			VerifyCallback(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockClaims, nil)

		store.EXPECT().
			Set(gomock.Any(), gomock.Cond(func(x any) bool {
				s, ok := x.(*session.Session)
				if !ok {
					return false
				}
				return s.UserID == "testuser@example.com" &&
					s.Provider == "openid" &&
					s.Claims["email"] == "testuser@example.com" &&
					s.Claims["name"] == "Test User"
			})).
			Return(nil)

		cookieManager.EXPECT().
			SetSessionCookie(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/openid/callback?state=mock-openid-state&openid.mode=id_res", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/dashboard" {
			t.Errorf("Expected redirect to /dashboard, got %s", loc)
		}
	})

	t.Run("User cancelled (openid.mode=cancel) -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := NewServer(nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/openid/callback?openid.mode=cancel", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Login cancelled") {
			t.Errorf("Expected 'Login cancelled', got %s", w.Body.String())
		}
	})

	t.Run("Error parameter present -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := NewServer(nil, nil, nil, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/openid/callback?error=access_denied", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("OpenID provider not configured -> 500", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := NewServer(nil, nil, nil, nil, nil) // no openIDProvider

		req := httptest.NewRequest(http.MethodGet, "/auth/openid/callback?state=test", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", w.Code)
		}
	})

	t.Run("State verification fails -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		openIDProvider := NewMockOpenIDProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, nil, nil, WithOpenIDProvider(openIDProvider))

		cookieManager.EXPECT().
			GetAuthState(gomock.Any()).
			Return(nil, http.ErrNoCookie)

		req := httptest.NewRequest(http.MethodGet, "/auth/openid/callback?state=test", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("State mismatch -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		openIDProvider := NewMockOpenIDProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, nil, nil, WithOpenIDProvider(openIDProvider))

		cookieManager.EXPECT().
			GetAuthState(gomock.Any()).
			Return(&cookie.AuthState{State: "stored-state", Provider: "openid"}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/openid/callback?state=incoming-state", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "State mismatch") {
			t.Errorf("Expected 'State mismatch', got %s", w.Body.String())
		}
	})

	t.Run("Provider mismatch -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		openIDProvider := NewMockOpenIDProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, nil, nil, WithOpenIDProvider(openIDProvider))

		cookieManager.EXPECT().
			GetAuthState(gomock.Any()).
			Return(&cookie.AuthState{State: "mock-state", Provider: "oidc"}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/openid/callback?state=mock-state", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Provider mismatch") {
			t.Errorf("Expected 'Provider mismatch', got %s", w.Body.String())
		}
	})

	t.Run("OpenID provider verification fails -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		openIDProvider := NewMockOpenIDProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, nil, nil, WithOpenIDProvider(openIDProvider))

		cookieManager.EXPECT().
			GetAuthState(gomock.Any()).
			Return(&cookie.AuthState{State: "mock-state", Provider: "openid"}, nil)

		cookieManager.EXPECT().
			ClearAuthState(gomock.Any(), gomock.Any())

		openIDProvider.EXPECT().
			VerifyCallback(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, errors.New("secret provider error detail"))

		req := httptest.NewRequest(http.MethodGet, "/auth/openid/callback?state=mock-state", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "OpenID verification failed") {
			t.Errorf("Expected 'OpenID verification failed', got %s", w.Body.String())
		}
		if strings.Contains(w.Body.String(), "secret provider error detail") {
			t.Errorf("Error leaked internal details: %s", w.Body.String())
		}
	})

	t.Run("Empty claims / no user ID -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		openIDProvider := NewMockOpenIDProvider(ctrl)

		server := NewServer(nil, nil, cookieManager, nil, nil, WithOpenIDProvider(openIDProvider))

		cookieManager.EXPECT().
			GetAuthState(gomock.Any()).
			Return(&cookie.AuthState{State: "mock-state", Provider: "openid"}, nil)

		cookieManager.EXPECT().
			ClearAuthState(gomock.Any(), gomock.Any())

		openIDProvider.EXPECT().
			VerifyCallback(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&openid.Claims{}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/openid/callback?state=mock-state", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Failed to extract user ID") {
			t.Errorf("Expected 'Failed to extract user ID', got %s", w.Body.String())
		}
	})

	t.Run("Missing email despite nickname and claimed_id -> 400 Bad Request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		openIDProvider := NewMockOpenIDProvider(ctrl)
		store := NewMockStore(ctrl)

		server := NewServer(store, nil, cookieManager, nil, nil, WithOpenIDProvider(openIDProvider))

		cookieManager.EXPECT().
			GetAuthState(gomock.Any()).
			Return(&cookie.AuthState{State: "mock-state", Provider: "openid"}, nil)

		cookieManager.EXPECT().
			ClearAuthState(gomock.Any(), gomock.Any())

		openIDProvider.EXPECT().
			VerifyCallback(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&openid.Claims{
				Nickname:  "nick",
				ClaimedID: "https://login.ubuntu.com/+id/user123",
			}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/openid/callback?state=mock-state", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Failed to extract user ID") {
			t.Errorf("Expected 'Failed to extract user ID', got %s", w.Body.String())
		}
	})

	t.Run("Invalid return_to in state falls back to /", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		openIDProvider := NewMockOpenIDProvider(ctrl)
		store := NewMockStore(ctrl)

		server := NewServer(store, nil, cookieManager, nil, nil, WithOpenIDProvider(openIDProvider))

		cookieManager.EXPECT().
			GetAuthState(gomock.Any()).
			Return(&cookie.AuthState{State: "mock-openid-state", ReturnTo: "https://evil.com", Provider: "openid"}, nil)

		cookieManager.EXPECT().
			ClearAuthState(gomock.Any(), gomock.Any())

		mockClaims := &openid.Claims{
			Email: "testuser@example.com",
		}

		openIDProvider.EXPECT().
			VerifyCallback(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(mockClaims, nil)

		store.EXPECT().
			Set(gomock.Any(), gomock.Any()).
			Return(nil)

		cookieManager.EXPECT().
			SetSessionCookie(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/openid/callback?state=mock-openid-state", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/" {
			t.Errorf("Expected redirect to /, got %s", loc)
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
		Decode("session_id", "test-session-value", gomock.Any()).
		Return("test-session-id", nil).
		AnyTimes() // May or may not be called depending on cookie presence

	// Expect the store Delete to be called
	store.EXPECT().
		Delete(gomock.Any(), "test-session-id").
		Return(nil).
		AnyTimes()

	cookieManager.EXPECT().
		ClearSessionCookie(gomock.Any(), gomock.Any())

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
}

// assertPrivateJSONHeaders verifies security headers required on all session endpoints.
func assertPrivateJSONHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := w.Header().Get("Vary"); got != "Cookie" {
		t.Errorf("Vary = %q, want %q", got, "Cookie")
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
	if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

func TestCrossOriginProtection(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		path         string
		host         string
		secFetchSite string
		origin       string
		wantBlocked  bool
	}{
		{
			name:         "DELETE /auth/sessions Sec-Fetch-Site same-origin allowed",
			method:       http.MethodDelete,
			path:         "/auth/sessions",
			host:         "sts.example.com",
			secFetchSite: "same-origin",
			wantBlocked:  false,
		},
		{
			name:         "DELETE /auth/sessions Sec-Fetch-Site cross-site rejected",
			method:       http.MethodDelete,
			path:         "/auth/sessions",
			host:         "sts.example.com",
			secFetchSite: "cross-site",
			origin:       "https://sts.example.com",
			wantBlocked:  true,
		},
		{
			name:         "DELETE /auth/sessions/{id} Sec-Fetch-Site same-site rejected",
			method:       http.MethodDelete,
			path:         "/auth/sessions/sess-1",
			host:         "sts.example.com",
			secFetchSite: "same-site",
			wantBlocked:  true,
		},
		{
			name:         "POST /auth/logout Sec-Fetch-Site cross-site rejected",
			method:       http.MethodPost,
			path:         "/auth/logout",
			host:         "sts.example.com",
			secFetchSite: "cross-site",
			wantBlocked:  true,
		},
		{
			name:        "Fallback Origin matching host allowed",
			method:      http.MethodDelete,
			path:        "/auth/sessions",
			host:        "sts.example.com",
			origin:      "https://sts.example.com",
			wantBlocked: false,
		},
		{
			name:        "Fallback Origin mismatched host rejected",
			method:      http.MethodDelete,
			path:        "/auth/sessions",
			host:        "sts.example.com",
			origin:      "https://evil.example.com",
			wantBlocked: true,
		},
		{
			name:        "Fallback Origin null rejected",
			method:      http.MethodDelete,
			path:        "/auth/sessions",
			host:        "sts.example.com",
			origin:      "null",
			wantBlocked: true,
		},
		{
			name:        "Both headers absent allowed for non-browser CLI callers",
			method:      http.MethodDelete,
			path:        "/auth/sessions",
			host:        "sts.example.com",
			wantBlocked: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			server := NewServer(NewMockStore(ctrl), nil, NewMockAuthCookieManager(ctrl), nil, nil)
			req := httptest.NewRequest(tc.method, "https://"+tc.host+tc.path, nil)
			req.Host = tc.host
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			server.Router().ServeHTTP(w, req)

			gotBlocked := w.Code == http.StatusForbidden
			if gotBlocked != tc.wantBlocked {
				t.Errorf("status = %d (blocked=%v), want blocked=%v", w.Code, gotBlocked, tc.wantBlocked)
			}
			if gotBlocked {
				assertPrivateJSONHeaders(t, w)
			}
		})
	}
}

// TestHandleSessions tests GET /auth/sessions self-service active session listing.
func TestHandleSessions(t *testing.T) {
	t.Run("Authenticated user lists multiple active sessions with minimal safe metadata", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockStore(ctrl)
		cm := NewMockAuthCookieManager(ctrl)
		server := NewServer(store, nil, cm, nil, nil)

		now := time.Now().UTC().Truncate(time.Second)
		sessA := &session.Session{
			SessionID:    "sess-a",
			UserID:       "alice@canonical.com",
			Provider:     "oidc",
			AccessToken:  "secret-access-token",
			IDToken:      "secret-id-token",
			RefreshToken: "secret-refresh-token",
			Claims:       map[string]interface{}{"email": "alice@canonical.com"},
			CreatedAt:    now.Add(-10 * time.Minute),
			ExpiresAt:    now.Add(50 * time.Minute),
		}
		sessB := &session.Session{
			SessionID:    "sess-b",
			UserID:       "alice@canonical.com",
			Provider:     "openid",
			AccessToken:  "other-secret-token",
			CreatedAt:    now.Add(-30 * time.Minute),
			ExpiresAt:    now.Add(30 * time.Minute),
		}

		cm.EXPECT().Decode("session_id", "encoded-a", gomock.Any()).Return("sess-a", nil)
		store.EXPECT().Get(gomock.Any(), "sess-a").Return(sessA, nil)
		store.EXPECT().ListUserSessions(gomock.Any(), "alice@canonical.com").Return([]*session.Session{sessA, sessB}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-a"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
		}
		assertPrivateJSONHeaders(t, w)

		body := w.Body.String()
		for _, forbidden := range []string{"secret-access-token", "secret-id-token", "secret-refresh-token", "other-secret-token", "access_token", "id_token", "refresh_token", "claims"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("response body leaked sensitive field/value %q: %s", forbidden, body)
			}
		}

		var resp sessionsListResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response failed: %v", err)
		}
		if len(resp.Sessions) != 2 {
			t.Fatalf("len(sessions) = %d, want 2", len(resp.Sessions))
		}
		if resp.Sessions[0].SessionID != "sess-a" || !resp.Sessions[0].IsCurrent || resp.Sessions[0].Provider != "oidc" {
			t.Errorf("unexpected session[0]: %+v", resp.Sessions[0])
		}
		if resp.Sessions[1].SessionID != "sess-b" || resp.Sessions[1].IsCurrent || resp.Sessions[1].Provider != "openid" {
			t.Errorf("unexpected session[1]: %+v", resp.Sessions[1])
		}
	})

	t.Run("Missing cookie returns 401 Unauthorized", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := NewServer(NewMockStore(ctrl), nil, NewMockAuthCookieManager(ctrl), nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		assertPrivateJSONHeaders(t, w)
	})

	t.Run("Expired or missing caller session returns 401 Unauthorized", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockStore(ctrl)
		cm := NewMockAuthCookieManager(ctrl)
		server := NewServer(store, nil, cm, nil, nil)

		cm.EXPECT().Decode("session_id", "encoded-expired", gomock.Any()).Return("sess-expired", nil)
		store.EXPECT().Get(gomock.Any(), "sess-expired").Return(nil, session.ErrSessionNotFound)

		req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-expired"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		assertPrivateJSONHeaders(t, w)
	})

	t.Run("Store unavailable during ListUserSessions returns 503 Service Unavailable", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockStore(ctrl)
		cm := NewMockAuthCookieManager(ctrl)
		server := NewServer(store, nil, cm, nil, nil)

		cm.EXPECT().Decode("session_id", "encoded-a", gomock.Any()).Return("sess-a", nil)
		store.EXPECT().Get(gomock.Any(), "sess-a").Return(&session.Session{SessionID: "sess-a", UserID: "alice@canonical.com"}, nil)
		store.EXPECT().ListUserSessions(gomock.Any(), "alice@canonical.com").Return(nil, errors.New("valkey connection refused"))

		req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-a"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", w.Code)
		}
		assertPrivateJSONHeaders(t, w)
	})
}

// TestHandleRevokeSession tests DELETE /auth/sessions/{session_id}.
func TestHandleRevokeSession(t *testing.T) {
	t.Run("Revoke another owned session leaves current cookie intact", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockStore(ctrl)
		cm := NewMockAuthCookieManager(ctrl)
		server := NewServer(store, nil, cm, nil, nil)

		cm.EXPECT().Decode("session_id", "encoded-cur", gomock.Any()).Return("sess-cur", nil)
		store.EXPECT().Get(gomock.Any(), "sess-cur").Return(&session.Session{SessionID: "sess-cur", UserID: "alice@canonical.com"}, nil)
		store.EXPECT().DeleteUserSession(gomock.Any(), "alice@canonical.com", "sess-other").Return(nil)
		// ClearSessionCookie must NOT be called when revoking another session.

		req := httptest.NewRequest(http.MethodDelete, "/auth/sessions/sess-other", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-cur"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
		}
		assertPrivateJSONHeaders(t, w)
		var resp revokeSessionResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || !resp.Revoked {
			t.Fatalf("unexpected body: %s (err=%v)", w.Body.String(), err)
		}
	})

	t.Run("Revoke current session deletes it and clears cookie", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockStore(ctrl)
		cm := NewMockAuthCookieManager(ctrl)
		server := NewServer(store, nil, cm, nil, nil)

		cm.EXPECT().Decode("session_id", "encoded-cur", gomock.Any()).Return("sess-cur", nil)
		store.EXPECT().Get(gomock.Any(), "sess-cur").Return(&session.Session{SessionID: "sess-cur", UserID: "alice@canonical.com"}, nil)
		store.EXPECT().DeleteUserSession(gomock.Any(), "alice@canonical.com", "sess-cur").Return(nil)
		cm.EXPECT().ClearSessionCookie(gomock.Any(), gomock.Any())

		req := httptest.NewRequest(http.MethodDelete, "/auth/sessions/sess-cur", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-cur"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
		}
		assertPrivateJSONHeaders(t, w)
	})

	t.Run("Revoke foreign session returns 404 Not Found without deleting", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockStore(ctrl)
		cm := NewMockAuthCookieManager(ctrl)
		server := NewServer(store, nil, cm, nil, nil)

		cm.EXPECT().Decode("session_id", "encoded-cur", gomock.Any()).Return("sess-cur", nil)
		store.EXPECT().Get(gomock.Any(), "sess-cur").Return(&session.Session{SessionID: "sess-cur", UserID: "alice@canonical.com"}, nil)
		store.EXPECT().DeleteUserSession(gomock.Any(), "alice@canonical.com", "sess-bob").Return(session.ErrSessionNotFound)

		req := httptest.NewRequest(http.MethodDelete, "/auth/sessions/sess-bob", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-cur"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", w.Code)
		}
		assertPrivateJSONHeaders(t, w)
	})

	t.Run("Revoke missing session returns 404 Not Found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockStore(ctrl)
		cm := NewMockAuthCookieManager(ctrl)
		server := NewServer(store, nil, cm, nil, nil)

		cm.EXPECT().Decode("session_id", "encoded-cur", gomock.Any()).Return("sess-cur", nil)
		store.EXPECT().Get(gomock.Any(), "sess-cur").Return(&session.Session{SessionID: "sess-cur", UserID: "alice@canonical.com"}, nil)
		store.EXPECT().DeleteUserSession(gomock.Any(), "alice@canonical.com", "sess-missing").Return(session.ErrSessionNotFound)

		req := httptest.NewRequest(http.MethodDelete, "/auth/sessions/sess-missing", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-cur"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", w.Code)
		}
		assertPrivateJSONHeaders(t, w)
	})

	t.Run("Cross-site CSRF rejected with 403 Forbidden before touching store", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := NewServer(NewMockStore(ctrl), nil, NewMockAuthCookieManager(ctrl), nil, nil)
		req := httptest.NewRequest(http.MethodDelete, "/auth/sessions/sess-other", nil)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-cur"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		assertPrivateJSONHeaders(t, w)
	})

	t.Run("Unauthenticated returns 401 Unauthorized", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := NewServer(NewMockStore(ctrl), nil, NewMockAuthCookieManager(ctrl), nil, nil)
		req := httptest.NewRequest(http.MethodDelete, "/auth/sessions/sess-other", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		assertPrivateJSONHeaders(t, w)
	})
}

// TestHandleRevokeAllSessions tests DELETE /auth/sessions.
func TestHandleRevokeAllSessions(t *testing.T) {
	t.Run("Default revokes all sessions and clears cookie", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockStore(ctrl)
		cm := NewMockAuthCookieManager(ctrl)
		server := NewServer(store, nil, cm, nil, nil)

		cm.EXPECT().Decode("session_id", "encoded-cur", gomock.Any()).Return("sess-cur", nil)
		store.EXPECT().Get(gomock.Any(), "sess-cur").Return(&session.Session{SessionID: "sess-cur", UserID: "alice@canonical.com"}, nil)
		store.EXPECT().RevokeUserSessionsExcept(gomock.Any(), "alice@canonical.com", "").Return(3, nil)
		cm.EXPECT().ClearSessionCookie(gomock.Any(), gomock.Any())

		req := httptest.NewRequest(http.MethodDelete, "/auth/sessions", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-cur"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
		}
		assertPrivateJSONHeaders(t, w)
		var resp revokeSessionsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.RevokedCount != 3 {
			t.Fatalf("unexpected body: %s (err=%v)", w.Body.String(), err)
		}
	})

	t.Run("exclude_current=true keeps current session and does not clear cookie", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockStore(ctrl)
		cm := NewMockAuthCookieManager(ctrl)
		server := NewServer(store, nil, cm, nil, nil)

		cm.EXPECT().Decode("session_id", "encoded-cur", gomock.Any()).Return("sess-cur", nil)
		store.EXPECT().Get(gomock.Any(), "sess-cur").Return(&session.Session{SessionID: "sess-cur", UserID: "alice@canonical.com"}, nil)
		store.EXPECT().RevokeUserSessionsExcept(gomock.Any(), "alice@canonical.com", "sess-cur").Return(2, nil)
		// ClearSessionCookie must NOT be called.

		req := httptest.NewRequest(http.MethodDelete, "/auth/sessions?exclude_current=true", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-cur"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
		}
		assertPrivateJSONHeaders(t, w)
		if got := w.Header().Get("Set-Cookie"); got != "" {
			t.Errorf("expected no Set-Cookie header when exclude_current=true, got %q", got)
		}
		var resp revokeSessionsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.RevokedCount != 2 {
			t.Fatalf("unexpected body: %s (err=%v)", w.Body.String(), err)
		}
	})

	t.Run("Invalid exclude_current returns 400 Bad Request without revoking", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockStore(ctrl)
		cm := NewMockAuthCookieManager(ctrl)
		server := NewServer(store, nil, cm, nil, nil)

		cm.EXPECT().Decode("session_id", "encoded-cur", gomock.Any()).Return("sess-cur", nil)
		store.EXPECT().Get(gomock.Any(), "sess-cur").Return(&session.Session{SessionID: "sess-cur", UserID: "alice@canonical.com"}, nil)

		req := httptest.NewRequest(http.MethodDelete, "/auth/sessions?exclude_current=notabool", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-cur"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		assertPrivateJSONHeaders(t, w)
	})

	t.Run("Cross-origin fallback Origin rejected with 403 Forbidden", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := NewServer(NewMockStore(ctrl), nil, NewMockAuthCookieManager(ctrl), nil, nil)
		req := httptest.NewRequest(http.MethodDelete, "https://sts.example.com/auth/sessions", nil)
		req.Host = "sts.example.com"
		req.Header.Set("Origin", "https://attacker.example.com")
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-cur"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		assertPrivateJSONHeaders(t, w)
	})

	t.Run("Unauthenticated returns 401 Unauthorized", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := NewServer(NewMockStore(ctrl), nil, NewMockAuthCookieManager(ctrl), nil, nil)
		req := httptest.NewRequest(http.MethodDelete, "/auth/sessions", nil)
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		assertPrivateJSONHeaders(t, w)
	})

	t.Run("Store unavailable returns 503 Service Unavailable", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockStore(ctrl)
		cm := NewMockAuthCookieManager(ctrl)
		server := NewServer(store, nil, cm, nil, nil)

		cm.EXPECT().Decode("session_id", "encoded-cur", gomock.Any()).Return("sess-cur", nil)
		store.EXPECT().Get(gomock.Any(), "sess-cur").Return(&session.Session{SessionID: "sess-cur", UserID: "alice@canonical.com"}, nil)
		store.EXPECT().RevokeUserSessionsExcept(gomock.Any(), "alice@canonical.com", "").Return(0, errors.New("valkey down"))

		req := httptest.NewRequest(http.MethodDelete, "/auth/sessions", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "encoded-cur"})
		w := httptest.NewRecorder()

		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", w.Code)
		}
		assertPrivateJSONHeaders(t, w)
	})
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

func TestHandleCallback_ClaimsNormalizationAndTenant(t *testing.T) {
	tests := []struct {
		name        string
		tenantClaim string
		rawClaims   map[string]interface{}
		wantReject  bool
		wantUserID  string
		wantClaims  map[string]interface{}
	}{
		{
			name:        "full OIDC profile and default tenant",
			tenantClaim: "",
			rawClaims: map[string]interface{}{
				"sub":                "sub-123",
				"email":              "alice@canonical.com",
				"name":               "Alice Smith",
				"given_name":         "Alice",
				"preferred_username": "alice",
				"tenant":             "canonical",
			},
			wantUserID: "alice@canonical.com",
			wantClaims: map[string]interface{}{
				"sub":                "sub-123",
				"email":              "alice@canonical.com",
				"name":               "Alice Smith",
				"given_name":         "Alice",
				"preferred_username": "alice",
				"tenant":             "canonical",
				"idp_provider":       "oidc",
			},
		},
		{
			name:        "custom tenant claim and given_name+family_name fallback",
			tenantClaim: "org",
			rawClaims: map[string]interface{}{
				"sub":         "sub-456",
				"email":       "bob@canonical.com",
				"given_name":  "Bob",
				"family_name": "Jones",
				"org":         "engineering",
			},
			wantUserID: "bob@canonical.com",
			wantClaims: map[string]interface{}{
				"sub":          "sub-456",
				"email":        "bob@canonical.com",
				"name":         "Bob Jones",
				"given_name":   "Bob",
				"tenant":       "engineering",
				"idp_provider": "oidc",
			},
		},
		{
			name:        "minimal claims and non-string tenant ignored",
			tenantClaim: "tenant",
			rawClaims: map[string]interface{}{
				"email":  "carol@canonical.com",
				"tenant": []string{"a", "b"},
			},
			wantUserID: "carol@canonical.com",
			wantClaims: map[string]interface{}{
				"email":        "carol@canonical.com",
				"idp_provider": "oidc",
			},
		},
		{
			name:        "email_verified string true accepted",
			tenantClaim: "tenant",
			rawClaims: map[string]interface{}{
				"sub":            "oidc-sub-str-true",
				"email":          "dave@canonical.com",
				"email_verified": "true",
			},
			wantUserID: "dave@canonical.com",
			wantClaims: map[string]interface{}{
				"sub":          "oidc-sub-str-true",
				"email":        "dave@canonical.com",
				"idp_provider": "oidc",
			},
		},
		{
			name:        "unverified email_verified=false rejects login without fallback",
			tenantClaim: "tenant",
			rawClaims: map[string]interface{}{
				"sub":                "oidc-sub-999",
				"email":              "victim@canonical.com",
				"email_verified":     false,
				"preferred_username": "victim@canonical.com",
				"nickname":           "victim",
				"name":               "Attacker",
			},
			wantReject: true,
		},
		{
			name:        "email_verified string false rejects login without fallback",
			tenantClaim: "tenant",
			rawClaims: map[string]interface{}{
				"sub":            "oidc-sub-str-false",
				"email":          "victim@canonical.com",
				"email_verified": "false",
			},
			wantReject: true,
		},
		{
			name:        "email_verified nil rejects login without fallback",
			tenantClaim: "tenant",
			rawClaims: map[string]interface{}{
				"sub":            "oidc-sub-nil",
				"email":          "victim@canonical.com",
				"email_verified": nil,
			},
			wantReject: true,
		},
		{
			name:        "missing email with sub/preferred_username/nickname rejects login",
			tenantClaim: "tenant",
			rawClaims: map[string]interface{}{
				"sub":                "oidc-sub-no-email",
				"preferred_username": "alice@canonical.com",
				"nickname":           "alice",
				"name":               "Alice",
			},
			wantReject: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			cookieManager := NewMockAuthCookieManager(ctrl)
			oidcProvider := NewMockOIDCProvider(ctrl)
			store := NewMockStore(ctrl)
			oauth2Token := NewMockOAuth2Token(ctrl)
			idToken := NewMockIDToken(ctrl)

			var opts []ServerOption
			if tc.tenantClaim != "" {
				opts = append(opts, WithTenantClaim(tc.tenantClaim))
			}
			server := NewServer(store, nil, cookieManager, oidcProvider, nil, opts...)

			cookieManager.EXPECT().GetAuthState(gomock.Any()).Return(&cookie.AuthState{State: "s1", Provider: "oidc"}, nil)
			cookieManager.EXPECT().ClearAuthState(gomock.Any(), gomock.Any())
			oidcProvider.EXPECT().Exchange(gomock.Any(), "c1").Return(oauth2Token, nil)
			oauth2Token.EXPECT().Extra("id_token").Return("raw-id")
			oidcProvider.EXPECT().VerifyIDToken(gomock.Any(), "raw-id").Return(idToken, nil)
			cookieManager.EXPECT().GetOIDCNonce(gomock.Any()).Return("n1", nil)
			cookieManager.EXPECT().ClearOIDCNonce(gomock.Any(), gomock.Any())
			idToken.EXPECT().GetNonce().Return("n1", nil)
			idToken.EXPECT().Claims(gomock.Any()).DoAndReturn(func(v interface{}) error {
				ptr := v.(*map[string]interface{})
				*ptr = tc.rawClaims
				return nil
			})

			var saved *session.Session
			if !tc.wantReject {
				oauth2Token.EXPECT().AccessToken().Return("at")
				idToken.EXPECT().GetOriginalToken().Return("it")
				oauth2Token.EXPECT().RefreshToken().Return("rt")
				store.EXPECT().Set(gomock.Any(), gomock.Any()).DoAndReturn(func(_ interface{}, s *session.Session, _ ...session.SetOption) error {
					saved = s
					return nil
				})
				cookieManager.EXPECT().SetSessionCookie(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			}

			req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=s1&code=c1", nil)
			w := httptest.NewRecorder()
			server.Router().ServeHTTP(w, req)

			if tc.wantReject {
				if w.Code != http.StatusInternalServerError {
					t.Fatalf("status = %d, want 500", w.Code)
				}
				if !strings.Contains(w.Body.String(), "Failed to extract user ID from ID Token") {
					t.Errorf("body = %q, want Failed to extract user ID from ID Token", w.Body.String())
				}
				return
			}

			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", w.Code)
			}
			if saved == nil {
				t.Fatal("expected saved session")
			}
			if saved.UserID != tc.wantUserID {
				t.Errorf("UserID = %q, want %q", saved.UserID, tc.wantUserID)
			}
			if len(saved.Claims) != len(tc.wantClaims) {
				t.Fatalf("Claims = %#v, want %#v", saved.Claims, tc.wantClaims)
			}
			for k, wantV := range tc.wantClaims {
				if saved.Claims[k] != wantV {
					t.Errorf("Claims[%q] = %#v, want %#v", k, saved.Claims[k], wantV)
				}
			}
		})
	}
}

func TestHandleMe(t *testing.T) {
	assertSecurityHeaders := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", got)
		}
		if got := w.Header().Get("Vary"); got != "Cookie" {
			t.Errorf("Vary = %q, want Cookie", got)
		}
		if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
		}
		if got := w.Header().Get("Set-Cookie"); got != "" {
			t.Errorf("unexpected Set-Cookie header: %q", got)
		}
	}

	t.Run("OIDC session with full profile and tenant -> 200", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		store := NewMockStore(ctrl)
		server := NewServer(store, nil, cookieManager, nil, nil)

		cookieManager.EXPECT().Decode("session_id", "enc-cookie", gomock.Any()).Return("sess-1", nil)
		store.EXPECT().Get(gomock.Any(), "sess-1").Return(&session.Session{
			SessionID:    "sess-1",
			UserID:       "alice@canonical.com",
			AccessToken:  "secret-access",
			IDToken:      "secret-id",
			RefreshToken: "secret-refresh",
			Claims: map[string]interface{}{
				"email":    "alice@canonical.com",
				"name":     "Alice Smith",
				"tenant":   "canonical",
				"nickname": "alice",
			},
		}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "enc-cookie"})
		w := httptest.NewRecorder()
		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		assertSecurityHeaders(t, w)

		var body map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if body["authenticated"] != true {
			t.Errorf("authenticated = %v, want true", body["authenticated"])
		}
		user := body["user"].(map[string]interface{})
		if user["id"] != "alice@canonical.com" || user["email"] != "alice@canonical.com" || user["name"] != "Alice Smith" || user["tenant"] != "canonical" {
			t.Errorf("unexpected user payload: %#v", user)
		}
		for _, forbidden := range []string{"secret-access", "secret-id", "secret-refresh", "sess-1", "nickname"} {
			if strings.Contains(w.Body.String(), forbidden) {
				t.Errorf("response leaked %q: %s", forbidden, w.Body.String())
			}
		}
	})

	t.Run("OpenID session without tenant omits tenant -> 200", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		store := NewMockStore(ctrl)
		server := NewServer(store, nil, cookieManager, nil, nil)

		cookieManager.EXPECT().Decode("session_id", "enc-cookie", gomock.Any()).Return("sess-2", nil)
		store.EXPECT().Get(gomock.Any(), "sess-2").Return(&session.Session{
			SessionID: "sess-2",
			UserID:    "u1@canonical.com",
			Provider:  "openid",
			Claims: map[string]interface{}{
				"email": "u1@canonical.com",
				"name":  "Ubuntu User",
			},
		}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "enc-cookie"})
		w := httptest.NewRecorder()
		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		assertSecurityHeaders(t, w)

		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		user := body["user"].(map[string]interface{})
		if _, exists := user["tenant"]; exists {
			t.Errorf("expected tenant to be omitted, got %#v", user["tenant"])
		}
	})

	t.Run("Session without email claim in Claims map omits email -> 200", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		store := NewMockStore(ctrl)
		server := NewServer(store, nil, cookieManager, nil, nil)

		cookieManager.EXPECT().Decode("session_id", "enc-cookie", gomock.Any()).Return("sess-3", nil)
		store.EXPECT().Get(gomock.Any(), "sess-3").Return(&session.Session{
			SessionID: "sess-3",
			UserID:    "u1_nick",
			Provider:  "openid",
			Claims: map[string]interface{}{
				"nickname": "u1_nick",
			},
		}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "enc-cookie"})
		w := httptest.NewRecorder()
		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		user := body["user"].(map[string]interface{})
		if user["id"] != "u1_nick" {
			t.Errorf("id = %v, want u1_nick", user["id"])
		}
		if _, exists := user["email"]; exists {
			t.Errorf("expected email to be omitted, got %#v", user["email"])
		}
	})

	t.Run("Session with nil Claims omits email even if UserID contains @ -> 200", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		store := NewMockStore(ctrl)
		server := NewServer(store, nil, cookieManager, nil, nil)

		cookieManager.EXPECT().Decode("session_id", "enc-cookie", gomock.Any()).Return("sess-4", nil)
		store.EXPECT().Get(gomock.Any(), "sess-4").Return(&session.Session{
			SessionID: "sess-4",
			UserID:    "unverified@upn.example.com",
		}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "enc-cookie"})
		w := httptest.NewRecorder()
		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		user := body["user"].(map[string]interface{})
		if user["id"] != "unverified@upn.example.com" {
			t.Errorf("id = %v, want unverified@upn.example.com", user["id"])
		}
		if _, exists := user["email"]; exists {
			t.Errorf("expected email to be omitted when Claims has no email, got %#v", user["email"])
		}
	})

	t.Run("Missing cookie -> 401", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		server := NewServer(NewMockStore(ctrl), nil, NewMockAuthCookieManager(ctrl), nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		w := httptest.NewRecorder()
		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		assertSecurityHeaders(t, w)
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body["authenticated"] != false {
			t.Errorf("authenticated = %v, want false", body["authenticated"])
		}
	})

	t.Run("Nil dependencies -> 500", func(t *testing.T) {
		server := NewServer(nil, nil, nil, nil, nil)
		for _, path := range []string{"/auth/me", "/auth/sessions"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			server.Router().ServeHTTP(w, req)

			if w.Code != http.StatusInternalServerError {
				t.Fatalf("%s status = %d, want 500", path, w.Code)
			}
			assertSecurityHeaders(t, w)
		}
	})

	t.Run("Tampered cookie -> 401 without store lookup", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		store := NewMockStore(ctrl)
		server := NewServer(store, nil, cookieManager, nil, nil)

		cookieManager.EXPECT().Decode("session_id", "bad-cookie", gomock.Any()).Return("", errors.New("aead failed"))

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "bad-cookie"})
		w := httptest.NewRecorder()
		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		assertSecurityHeaders(t, w)
	})

	t.Run("Revoked or expired session -> 401", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		store := NewMockStore(ctrl)
		server := NewServer(store, nil, cookieManager, nil, nil)

		cookieManager.EXPECT().Decode("session_id", "enc-cookie", gomock.Any()).Return("sess-gone", nil)
		store.EXPECT().Get(gomock.Any(), "sess-gone").Return(nil, session.ErrSessionNotFound)

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "enc-cookie"})
		w := httptest.NewRecorder()
		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		assertSecurityHeaders(t, w)
	})

	t.Run("Session store unavailable -> 503", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cookieManager := NewMockAuthCookieManager(ctrl)
		store := NewMockStore(ctrl)
		server := NewServer(store, nil, cookieManager, nil, nil)

		cookieManager.EXPECT().Decode("session_id", "enc-cookie", gomock.Any()).Return("sess-1", nil)
		store.EXPECT().Get(gomock.Any(), "sess-1").Return(nil, errors.New("valkey connection refused"))

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "enc-cookie"})
		w := httptest.NewRecorder()
		server.Router().ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", w.Code)
		}
		assertSecurityHeaders(t, w)
	})
}

func TestHandleCallback_ReauthCleansUpPreviousSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cookieManager := NewMockAuthCookieManager(ctrl)
	oidcProvider := NewMockOIDCProvider(ctrl)
	store := NewMockStore(ctrl)
	oauth2Token := NewMockOAuth2Token(ctrl)
	idToken := NewMockIDToken(ctrl)

	server := NewServer(store, nil, cookieManager, oidcProvider, nil)

	cookieManager.EXPECT().GetAuthState(gomock.Any()).Return(&cookie.AuthState{State: "s1", Provider: "oidc"}, nil)
	cookieManager.EXPECT().ClearAuthState(gomock.Any(), gomock.Any())
	oidcProvider.EXPECT().Exchange(gomock.Any(), "c1").Return(oauth2Token, nil)
	oauth2Token.EXPECT().Extra("id_token").Return("raw-id")
	oidcProvider.EXPECT().VerifyIDToken(gomock.Any(), "raw-id").Return(idToken, nil)
	cookieManager.EXPECT().GetOIDCNonce(gomock.Any()).Return("n1", nil)
	cookieManager.EXPECT().ClearOIDCNonce(gomock.Any(), gomock.Any())
	idToken.EXPECT().GetNonce().Return("n1", nil)
	idToken.EXPECT().Claims(gomock.Any()).DoAndReturn(func(v interface{}) error {
		ptr := v.(*map[string]interface{})
		*ptr = map[string]interface{}{"email": "alice@canonical.com"}
		return nil
	})
	oauth2Token.EXPECT().AccessToken().Return("at")
	idToken.EXPECT().GetOriginalToken().Return("it")
	oauth2Token.EXPECT().RefreshToken().Return("rt")
	store.EXPECT().Set(gomock.Any(), gomock.Any()).Return(nil)
	cookieManager.EXPECT().Decode("session_id", "old-enc-cookie", gomock.Any()).Return("old-sess-id", nil)
	store.EXPECT().Delete(gomock.Any(), "old-sess-id").Return(nil)
	cookieManager.EXPECT().SetSessionCookie(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=s1&code=c1", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "old-enc-cookie"})
	w := httptest.NewRecorder()
	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
}

func TestHandleOpenIDCallback_ReauthCleansUpPreviousSessionAndRecordsMetric(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cookieManager := NewMockAuthCookieManager(ctrl)
	openIDProvider := NewMockOpenIDProvider(ctrl)
	store := NewMockStore(ctrl)

	mp, err := observability.NewMetricsProvider(observability.MetricsConfig{
		Enabled:        true,
		ServiceName:    "sts-test",
		ServiceVersion: "test",
	})
	if err != nil {
		t.Fatalf("NewMetricsProvider failed: %v", err)
	}
	t.Cleanup(func() { _ = mp.Shutdown(t.Context()) })
	obs := &observability.Observability{MetricsProvider: mp}

	server := NewServer(store, nil, cookieManager, nil, obs, WithOpenIDProvider(openIDProvider))

	cookieManager.EXPECT().GetAuthState(gomock.Any()).Return(&cookie.AuthState{State: "st1", ReturnTo: "/", Provider: "openid"}, nil)
	cookieManager.EXPECT().ClearAuthState(gomock.Any(), gomock.Any())
	openIDProvider.EXPECT().VerifyCallback(gomock.Any(), gomock.Any(), gomock.Any()).Return(&openid.Claims{
		Email:    "alice@canonical.com",
		FullName: "Alice Smith",
	}, nil)
	store.EXPECT().Set(gomock.Any(), gomock.Any()).Return(nil)
	gomock.InOrder(
		cookieManager.EXPECT().SetSessionCookie(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil),
		cookieManager.EXPECT().Decode("session_id", "old-openid-cookie", gomock.Any()).Return("old-openid-sess", nil),
		store.EXPECT().Delete(gomock.Any(), "old-openid-sess").Return(nil),
	)

	req := httptest.NewRequest(http.MethodGet, "/auth/openid/callback?state=st1&openid.mode=id_res", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "old-openid-cookie"})
	w := httptest.NewRecorder()
	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}

	// Verify sts_sessions_created metric incremented.
	metricsW := httptest.NewRecorder()
	mp.GetPrometheusHandler().ServeHTTP(metricsW, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metricsW.Body.String(), "sts_sessions_created") {
		t.Errorf("expected sts_sessions_created metric in /metrics output, got:\n%s", metricsW.Body.String())
	}
}
