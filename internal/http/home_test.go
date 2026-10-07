// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

//go:generate mockgen -build_flags=--mod=mod -package httpserver -destination ./mock_interfaces.go github.com/canonical/secure-token-service/internal/http AuthCookieManager,KeyManager,OIDCProvider,OpenIDProvider
//go:generate mockgen -build_flags=--mod=mod -package httpserver -destination ./mock_store.go -source=../session/store.go

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/canonical/secure-token-service/internal/session"
	"go.uber.org/mock/gomock"
)

// TestHandleHome_NoSessionCookie tests the handler when no session cookie is present
func TestHandleHome_NoSessionCookie(t *testing.T) {
	server := NewServer(nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	server.handleHome(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Secure Token Service") {
		t.Error("Expected unauthenticated home page to contain title")
	}
	if !strings.Contains(body, "/auth/login") {
		t.Error("Expected login link in unauthenticated page")
	}
}

// TestHandleHome_EmptySessionCookie tests the handler with an empty session cookie
func TestHandleHome_EmptySessionCookie(t *testing.T) {
	server := NewServer(nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: ""})
	w := httptest.NewRecorder()

	server.handleHome(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Secure Token Service") {
		t.Error("Expected unauthenticated home page")
	}
}

// TestHandleHome_InvalidSessionCookie tests the handler with an invalid session cookie
func TestHandleHome_InvalidSessionCookie(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCookieManager := NewMockAuthCookieManager(ctrl)
	mockCookieManager.EXPECT().
		Decode("session_id", "invalid_cookie_value").
		Return("", errors.New("decode error"))

	server := NewServer(nil, nil, mockCookieManager, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "invalid_cookie_value"})
	w := httptest.NewRecorder()

	server.handleHome(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Secure Token Service") {
		t.Error("Expected unauthenticated home page after decode error")
	}
}

// TestHandleHome_SessionNotFound tests when session doesn't exist in store
func TestHandleHome_SessionNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCookieManager := NewMockAuthCookieManager(ctrl)
	mockSessionStore := NewMockStore(ctrl)

	sessionID := "test-session-id"
	mockCookieManager.EXPECT().
		Decode("session_id", "valid_cookie").
		Return(sessionID, nil)

	mockSessionStore.EXPECT().
		Get(gomock.Any(), sessionID).
		Return(nil, errors.New("session not found"))

	server := NewServer(mockSessionStore, nil, mockCookieManager, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "valid_cookie"})
	w := httptest.NewRecorder()

	server.handleHome(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Secure Token Service") {
		t.Error("Expected unauthenticated home page when session not found")
	}
}

// TestHandleHome_SessionReturnsNil tests when session store returns nil without error
func TestHandleHome_SessionReturnsNil(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCookieManager := NewMockAuthCookieManager(ctrl)
	mockSessionStore := NewMockStore(ctrl)

	sessionID := "test-session-id"
	mockCookieManager.EXPECT().
		Decode("session_id", "valid_cookie").
		Return(sessionID, nil)

	mockSessionStore.EXPECT().
		Get(gomock.Any(), sessionID).
		Return(nil, nil)

	server := NewServer(mockSessionStore, nil, mockCookieManager, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "valid_cookie"})
	w := httptest.NewRecorder()

	server.handleHome(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Secure Token Service") {
		t.Error("Expected unauthenticated home page when session is nil")
	}
}

// TestHandleHome_Authenticated tests with a valid session
func TestHandleHome_Authenticated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCookieManager := NewMockAuthCookieManager(ctrl)
	mockSessionStore := NewMockStore(ctrl)

	sessionID := "test-session-id"
	testSession := &session.Session{
		SessionID:    sessionID,
		UserID:       "user123",
		AccessToken:  "access_token_1234567890",
		IDToken:      "id_token_1234567890",
		RefreshToken: "refresh_token_1234567890",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now().Add(-1 * time.Hour),
	}

	mockCookieManager.EXPECT().
		Decode("session_id", "valid_cookie").
		Return(sessionID, nil)

	mockSessionStore.EXPECT().
		Get(gomock.Any(), sessionID).
		Return(testSession, nil)

	server := NewServer(mockSessionStore, nil, mockCookieManager, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "valid_cookie"})
	w := httptest.NewRecorder()

	server.handleHome(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Session Information") {
		t.Error("Expected authenticated home page to contain 'Session Information'")
	}
	if !strings.Contains(body, testSession.UserID) {
		t.Error("Expected authenticated home page to contain user ID")
	}
	if !strings.Contains(body, sessionID) {
		t.Error("Expected authenticated home page to contain session ID")
	}
	if !strings.Contains(body, "/auth/logout") {
		t.Error("Expected logout form in authenticated page")
	}
}

// TestHandleHome_TokenMasking tests that tokens are properly masked
func TestHandleHome_TokenMasking(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCookieManager := NewMockAuthCookieManager(ctrl)
	mockSessionStore := NewMockStore(ctrl)

	sessionID := "test-session-id"
	testSession := &session.Session{
		SessionID:    sessionID,
		UserID:       "user123",
		AccessToken:  "this_is_a_very_long_access_token_1234567890",
		IDToken:      "this_is_a_very_long_id_token_1234567890",
		RefreshToken: "short",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}

	mockCookieManager.EXPECT().
		Decode("session_id", "valid_cookie").
		Return(sessionID, nil)

	mockSessionStore.EXPECT().
		Get(gomock.Any(), sessionID).
		Return(testSession, nil)

	server := NewServer(mockSessionStore, nil, mockCookieManager, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "valid_cookie"})
	w := httptest.NewRecorder()

	server.handleHome(w, req)

	body := w.Body.String()

	// Verify tokens are masked (last 10 chars shown for long tokens)
	if !strings.Contains(body, "...1234567890") {
		t.Error("Expected long access token to be masked with last 10 chars")
	}

	// Short tokens should show as ***
	if !strings.Contains(body, "***") {
		t.Error("Expected short refresh token to be masked as ***")
	}

	// Original full token should NOT appear
	if strings.Contains(body, "this_is_a_very_long_access_token_1234567890") {
		t.Error("Expected full access token to NOT appear in output")
	}
}

// TestHandleHome_NoRefreshToken tests behavior when refresh token is empty
func TestHandleHome_NoRefreshToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCookieManager := NewMockAuthCookieManager(ctrl)
	mockSessionStore := NewMockStore(ctrl)

	sessionID := "test-session-id"
	testSession := &session.Session{
		SessionID:    sessionID,
		UserID:       "user123",
		AccessToken:  "access_token_1234567890",
		IDToken:      "id_token_1234567890",
		RefreshToken: "", // Empty refresh token
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}

	mockCookieManager.EXPECT().
		Decode("session_id", "valid_cookie").
		Return(sessionID, nil)

	mockSessionStore.EXPECT().
		Get(gomock.Any(), sessionID).
		Return(testSession, nil)

	server := NewServer(mockSessionStore, nil, mockCookieManager, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "valid_cookie"})
	w := httptest.NewRecorder()

	server.handleHome(w, req)

	body := w.Body.String()

	if !strings.Contains(body, "N/A") {
		t.Error("Expected 'N/A' for empty refresh token")
	}
}

// TestHandleHome_ExpiredSession tests rendering of an expired session
func TestHandleHome_ExpiredSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCookieManager := NewMockAuthCookieManager(ctrl)
	mockSessionStore := NewMockStore(ctrl)

	sessionID := "test-session-id"
	testSession := &session.Session{
		SessionID:    sessionID,
		UserID:       "user123",
		AccessToken:  "access_token_1234567890",
		IDToken:      "id_token_1234567890",
		RefreshToken: "refresh_token_1234567890",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // Expired
		CreatedAt:    time.Now().Add(-2 * time.Hour),
	}

	mockCookieManager.EXPECT().
		Decode("session_id", "valid_cookie").
		Return(sessionID, nil)

	mockSessionStore.EXPECT().
		Get(gomock.Any(), sessionID).
		Return(testSession, nil)

	server := NewServer(mockSessionStore, nil, mockCookieManager, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "valid_cookie"})
	w := httptest.NewRecorder()

	server.handleHome(w, req)

	body := w.Body.String()

	if !strings.Contains(body, "Expired") {
		t.Error("Expected expired session to show 'Expired' status")
	}
	if !strings.Contains(body, "expired") {
		t.Error("Expected expired session to have 'expired' CSS class")
	}
}

// TestHandleHome_ActiveSession tests rendering of an active session
func TestHandleHome_ActiveSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCookieManager := NewMockAuthCookieManager(ctrl)
	mockSessionStore := NewMockStore(ctrl)

	sessionID := "test-session-id"
	testSession := &session.Session{
		SessionID:    sessionID,
		UserID:       "user123",
		AccessToken:  "access_token_1234567890",
		IDToken:      "id_token_1234567890",
		RefreshToken: "refresh_token_1234567890",
		ExpiresAt:    time.Now().Add(1 * time.Hour), // Active
		CreatedAt:    time.Now().Add(-1 * time.Hour),
	}

	mockCookieManager.EXPECT().
		Decode("session_id", "valid_cookie").
		Return(sessionID, nil)

	mockSessionStore.EXPECT().
		Get(gomock.Any(), sessionID).
		Return(testSession, nil)

	server := NewServer(mockSessionStore, nil, mockCookieManager, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "valid_cookie"})
	w := httptest.NewRecorder()

	server.handleHome(w, req)

	body := w.Body.String()

	if !strings.Contains(body, "Active") {
		t.Error("Expected active session to show 'Active' status")
	}
	if !strings.Contains(body, "active") {
		t.Error("Expected active session to have 'active' CSS class")
	}
}

// TestRenderUnauthenticatedHome tests the unauthenticated home page rendering
func TestRenderUnauthenticatedHome(t *testing.T) {
	w := httptest.NewRecorder()
	renderUnauthenticatedHome(w)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("Expected Content-Type 'text/html; charset=utf-8', got '%s'", contentType)
	}

	body := w.Body.String()
	expectedStrings := []string{
		"<!DOCTYPE html>",
		"Secure Token Service",
		"/auth/login",
		"/auth/login?provider=oidc",
		"/auth/login?provider=openid",
		"Log In with OIDC",
		"Log In with Ubuntu One",
		"🔐",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(body, expected) {
			t.Errorf("Expected HTML to contain '%s'", expected)
		}
	}
}

// TestRenderAuthenticatedHome tests the authenticated home page rendering
func TestRenderAuthenticatedHome(t *testing.T) {
	testSession := &session.Session{
		SessionID:    "session123",
		UserID:       "user456",
		AccessToken:  "access_token_1234567890",
		IDToken:      "id_token_1234567890",
		RefreshToken: "refresh_token_1234567890",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now().Add(-1 * time.Hour),
	}

	w := httptest.NewRecorder()
	renderAuthenticatedHome(w, testSession)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("Expected Content-Type 'text/html; charset=utf-8', got '%s'", contentType)
	}

	body := w.Body.String()
	expectedStrings := []string{
		"<!DOCTYPE html>",
		"Session Information",
		testSession.UserID,
		testSession.SessionID,
		"User ID",
		"Session ID",
		"Session Status",
		"Expires At",
		"Created At",
		"Access Token",
		"ID Token",
		"Refresh Token",
		"/auth/logout",
		"Logout",
		"👤",
		"🔑",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(body, expected) {
			t.Errorf("Expected HTML to contain '%s'", expected)
		}
	}
}

// TestRenderAuthenticatedHome_OpenID tests authenticated home page rendering with OpenID 2.0 session
func TestRenderAuthenticatedHome_OpenID(t *testing.T) {
	testSession := &session.Session{
		SessionID: "openid-session-456",
		UserID:    "alice@ubuntu.com",
		Provider:  "openid",
		Claims: map[string]interface{}{
			"email":    "alice@ubuntu.com",
			"nickname": "alice",
			"fullname": "Alice Canonical",
		},
		AccessToken:  "", // OpenID 2.0 has no OAuth2 tokens
		IDToken:      "",
		RefreshToken: "",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
		CreatedAt:    time.Now().Add(-10 * time.Minute),
	}

	w := httptest.NewRecorder()
	renderAuthenticatedHome(w, testSession)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body := w.Body.String()
	expectedStrings := []string{
		"<!DOCTYPE html>",
		"Session Information",
		"alice@ubuntu.com",
		"openid-session-456",
		"Ubuntu One (OpenID 2.0)",
		"provider-openid",
		"Normalized Claims",
		"alice@ubuntu.com",
		"alice",
		"Alice Canonical",
		"N/A", // Tokens show as N/A
		"/auth/login?provider=oidc",
		"/auth/login?provider=openid",
		"/auth/logout",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(body, expected) {
			t.Errorf("Expected HTML to contain '%s'", expected)
		}
	}
}


// TestGetStatusClass tests the getStatusClass helper function
func TestGetStatusClass(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  string
	}{
		{
			name:      "active session - future expiration",
			expiresAt: time.Now().Add(1 * time.Hour),
			expected:  "active",
		},
		{
			name:      "expired session - past expiration",
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  "expired",
		},
		{
			name:      "just expired - 1 second ago",
			expiresAt: time.Now().Add(-1 * time.Second),
			expected:  "expired",
		},
		{
			name:      "about to expire - 1 second from now",
			expiresAt: time.Now().Add(1 * time.Second),
			expected:  "active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStatusClass(tt.expiresAt)
			if result != tt.expected {
				t.Errorf("getStatusClass(%v) = %s, expected %s", tt.expiresAt, result, tt.expected)
			}
		})
	}
}

// TestGetStatusText tests the getStatusText helper function
func TestGetStatusText(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  string
	}{
		{
			name:      "active session - future expiration",
			expiresAt: time.Now().Add(1 * time.Hour),
			expected:  "Active",
		},
		{
			name:      "expired session - past expiration",
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  "Expired",
		},
		{
			name:      "just expired - 1 second ago",
			expiresAt: time.Now().Add(-1 * time.Second),
			expected:  "Expired",
		},
		{
			name:      "about to expire - 1 second from now",
			expiresAt: time.Now().Add(1 * time.Second),
			expected:  "Active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStatusText(tt.expiresAt)
			if result != tt.expected {
				t.Errorf("getStatusText(%v) = %s, expected %s", tt.expiresAt, result, tt.expected)
			}
		})
	}
}

// TestHandleHome_ContextPropagation ensures request context is properly used
func TestHandleHome_ContextPropagation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCookieManager := NewMockAuthCookieManager(ctrl)
	mockSessionStore := NewMockStore(ctrl)

	sessionID := "test-session-id"
	mockCookieManager.EXPECT().
		Decode("session_id", "valid_cookie").
		Return(sessionID, nil)

	// Use gomock.Any() to match the context, but ensure Get is called
	mockSessionStore.EXPECT().
		Get(gomock.Any(), sessionID).
		DoAndReturn(func(ctx context.Context, id string) (*session.Session, error) {
			// Verify context is not nil
			if ctx == nil {
				t.Error("Expected non-nil context to be passed to SessionStore.Get")
			}
			return nil, errors.New("session not found")
		})

	server := NewServer(mockSessionStore, nil, mockCookieManager, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "valid_cookie"})
	w := httptest.NewRecorder()

	server.handleHome(w, req)
}

// TestGetProviderDisplayName tests the getProviderDisplayName helper function
func TestGetProviderDisplayName(t *testing.T) {
	tests := []struct {
		provider string
		expected string
	}{
		{"openid", "Ubuntu One (OpenID 2.0)"},
		{"oidc", "OpenID Connect (OIDC)"},
		{"", "OIDC"},
		{"custom", "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			got := getProviderDisplayName(tt.provider)
			if got != tt.expected {
				t.Errorf("getProviderDisplayName(%q) = %q, expected %q", tt.provider, got, tt.expected)
			}
		})
	}
}

