// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/canonical/secure-token-service/internal/session"
)

func TestHandleHome_Unauthenticated(t *testing.T) {
	server := NewServer(nil, nil, nil, nil, nil)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	server.handleHome(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()

	// Verify it's the unauthenticated page
	if !strings.Contains(body, "Log In") {
		t.Error("Expected login button in unauthenticated page")
	}

	if !strings.Contains(body, "/auth/login") {
		t.Error("Expected login link to /auth/login")
	}

	if !strings.Contains(body, "Secure Token Service") {
		t.Error("Expected title in unauthenticated page")
	}
}

func TestHandleHome_Authenticated(t *testing.T) {
	// Create mock session store
	sessionStore := &MockSessionStore{}

	// Create mock cookie manager
	cookieManager := NewMockCookieManager()

	server := NewServer(sessionStore, nil, cookieManager, nil, nil)

	// Create a test session
	testSession := &session.Session{
		SessionID:    "test-session-123",
		UserID:       "user-456",
		AccessToken:  "access_token_1234567890abcdef",
		IDToken:      "id_token_1234567890abcdef",
		RefreshToken: "refresh_token_1234567890abcdef",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now().Add(-10 * time.Minute),
	}

	sessionStore.lastSession = testSession

	// Encode session cookie
	encodedCookie, _ := cookieManager.Encode("session_id", testSession.SessionID)

	// Create request with session cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: encodedCookie,
	})

	w := httptest.NewRecorder()

	server.handleHome(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()

	// Verify it's the authenticated page
	if !strings.Contains(body, "Session Information") {
		t.Error("Expected 'Session Information' title")
	}

	if !strings.Contains(body, testSession.UserID) {
		t.Errorf("Expected user ID '%s' in page", testSession.UserID)
	}

	if !strings.Contains(body, testSession.SessionID) {
		t.Errorf("Expected session ID '%s' in page", testSession.SessionID)
	}

	// Verify tokens are masked (last 10 chars shown)
	if !strings.Contains(body, "...7890abcdef") {
		t.Error("Expected masked access token in page")
	}

	// Verify logout button
	if !strings.Contains(body, "/auth/logout") {
		t.Error("Expected logout form action")
	}

	if !strings.Contains(body, "Logout") {
		t.Error("Expected logout button")
	}
}

func TestHandleHome_InvalidSessionCookie(t *testing.T) {
	sessionStore := &MockSessionStore{}
	cookieManager := NewMockCookieManager()

	server := NewServer(sessionStore, nil, cookieManager, nil, nil)

	// Create request with invalid cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: "invalid-cookie-value",
	})

	w := httptest.NewRecorder()

	server.handleHome(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()

	// Should fall back to unauthenticated page
	if !strings.Contains(body, "Log In") {
		t.Error("Expected login button when session cookie is invalid")
	}
}

func TestHandleHome_ExpiredSession(t *testing.T) {
	sessionStore := &MockSessionStore{}
	cookieManager := NewMockCookieManager()

	server := NewServer(sessionStore, nil, cookieManager, nil, nil)

	// Create an expired session
	expiredSession := &session.Session{
		SessionID:    "expired-session",
		UserID:       "user-789",
		AccessToken:  "access_token_expired",
		IDToken:      "id_token_expired",
		RefreshToken: "",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		CreatedAt:    time.Now().Add(-2 * time.Hour),
	}

	sessionStore.lastSession = expiredSession

	encodedCookie, _ := cookieManager.Encode("session_id", expiredSession.SessionID)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: encodedCookie,
	})

	w := httptest.NewRecorder()

	server.handleHome(w, req)

	body := w.Body.String()

	// Should still show the session, but marked as expired
	if !strings.Contains(body, "Expired") {
		t.Error("Expected 'Expired' status for expired session")
	}
}
