// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package grpcserver

import (
	"context"
	"errors"
	"testing"
	"time"

	stsv1 "github.com/canonical/secure-token-service/api/proto/v1"
	"github.com/canonical/secure-token-service/internal/session"
)

// Mock implementations

type MockCookieManager struct {
	decodeFunc func(name, value string) (string, error)
	encodeFunc func(name, value string) (string, error)
}

func (m *MockCookieManager) Decode(name, value string) (string, error) {
	if m.decodeFunc != nil {
		return m.decodeFunc(name, value)
	}
	return value, nil // Default: return as-is
}

func (m *MockCookieManager) Encode(name, value string) (string, error) {
	if m.encodeFunc != nil {
		return m.encodeFunc(name, value)
	}
	return value, nil // Default: return as-is
}

type MockSessionStore struct {
	getFunc                func(ctx context.Context, id string) (*session.Session, error)
	setFunc                func(ctx context.Context, sess *session.Session) error
	deleteFunc             func(ctx context.Context, id string) error
	revokeUserSessionsFunc func(ctx context.Context, userID string) error
}

func (m *MockSessionStore) Get(ctx context.Context, id string) (*session.Session, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, id)
	}
	return nil, errors.New("session not found")
}

func (m *MockSessionStore) Set(ctx context.Context, sess *session.Session) error {
	if m.setFunc != nil {
		return m.setFunc(ctx, sess)
	}
	return nil
}

func (m *MockSessionStore) Delete(ctx context.Context, id string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id)
	}
	return nil
}

func (m *MockSessionStore) RevokeUserSessions(ctx context.Context, userID string) error {
	if m.revokeUserSessionsFunc != nil {
		return m.revokeUserSessionsFunc(ctx, userID)
	}
	return nil
}

type MockKeyManager struct {
	mintTokenFunc func(subject, issuer, audience string, expirySeconds int, claims map[string]interface{}) (string, error)
}

func (m *MockKeyManager) MintToken(subject, issuer, audience string, expirySeconds int, claims map[string]interface{}) (string, error) {
	if m.mintTokenFunc != nil {
		return m.mintTokenFunc(subject, issuer, audience, expirySeconds, claims)
	}
	return "mock-jwt-token", nil
}

// Tests

func TestExchangeSession_Success(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	cookieManager := &MockCookieManager{
		decodeFunc: func(name, value string) (string, error) {
			if name == "session_id" && value == "encoded-cookie" {
				return "session-123", nil
			}
			return "", errors.New("invalid cookie")
		},
	}

	sessionStore := &MockSessionStore{
		getFunc: func(ctx context.Context, id string) (*session.Session, error) {
			if id == "session-123" {
				return &session.Session{
					SessionID:    "session-123",
					UserID:       "user-456",
					AccessToken:  "upstream-token",
					IDToken:      "id-token",
					RefreshToken: "refresh-token",
					ExpiresAt:    time.Now().Add(1 * time.Hour),
					CreatedAt:    time.Now(),
				}, nil
			}
			return nil, errors.New("session not found")
		},
	}

	keyManager := &MockKeyManager{
		mintTokenFunc: func(subject, issuer, audience string, expirySeconds int, claims map[string]interface{}) (string, error) {
			if subject == "user-456" {
				return "internal-jwt-token", nil
			}
			return "", errors.New("failed to mint token")
		},
	}

	// Create server
	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600)

	// Test exchange
	req := &stsv1.ExchangeRequest{
		SessionCookie: "encoded-cookie",
	}

	resp, err := server.ExchangeSession(ctx, req)

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if resp.AccessToken != "internal-jwt-token" {
		t.Errorf("Expected access token 'internal-jwt-token', got: %s", resp.AccessToken)
	}

	if resp.ExpiresIn != 3600 {
		t.Errorf("Expected expires_in 3600, got: %d", resp.ExpiresIn)
	}
}

func TestExchangeSession_EmptyCookie(t *testing.T) {
	ctx := context.Background()

	server := NewServer(&MockSessionStore{}, &MockKeyManager{}, &MockCookieManager{}, "issuer", "audience", 3600)

	req := &stsv1.ExchangeRequest{
		SessionCookie: "",
	}

	_, err := server.ExchangeSession(ctx, req)

	if err == nil {
		t.Fatal("Expected error for empty session cookie")
	}

	// Check that it's an InvalidArgument error
	if err.Error() != "rpc error: code = InvalidArgument desc = session_cookie is required" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestExchangeSession_InvalidCookie(t *testing.T) {
	ctx := context.Background()

	cookieManager := &MockCookieManager{
		decodeFunc: func(name, value string) (string, error) {
			return "", errors.New("invalid cookie format")
		},
	}

	server := NewServer(&MockSessionStore{}, &MockKeyManager{}, cookieManager, "issuer", "audience", 3600)

	req := &stsv1.ExchangeRequest{
		SessionCookie: "bad-cookie",
	}

	_, err := server.ExchangeSession(ctx, req)

	if err == nil {
		t.Fatal("Expected error for invalid cookie")
	}

	if err.Error() != "rpc error: code = InvalidArgument desc = invalid session cookie" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestExchangeSession_SessionNotFound(t *testing.T) {
	ctx := context.Background()

	cookieManager := &MockCookieManager{
		decodeFunc: func(name, value string) (string, error) {
			return "nonexistent-session", nil
		},
	}

	sessionStore := &MockSessionStore{
		getFunc: func(ctx context.Context, id string) (*session.Session, error) {
			return nil, errors.New("session not found")
		},
	}

	server := NewServer(sessionStore, &MockKeyManager{}, cookieManager, "issuer", "audience", 3600)

	req := &stsv1.ExchangeRequest{
		SessionCookie: "valid-cookie",
	}

	_, err := server.ExchangeSession(ctx, req)

	if err == nil {
		t.Fatal("Expected error for nonexistent session")
	}

	if err.Error() != "rpc error: code = NotFound desc = session not found" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestExchangeSession_MintTokenFailure(t *testing.T) {
	ctx := context.Background()

	cookieManager := &MockCookieManager{
		decodeFunc: func(name, value string) (string, error) {
			return "session-123", nil
		},
	}

	sessionStore := &MockSessionStore{
		getFunc: func(ctx context.Context, id string) (*session.Session, error) {
			return &session.Session{
				SessionID: "session-123",
				UserID:    "user-456",
			}, nil
		},
	}

	keyManager := &MockKeyManager{
		mintTokenFunc: func(subject, issuer, audience string, expirySeconds int, claims map[string]interface{}) (string, error) {
			return "", errors.New("key signing failed")
		},
	}

	server := NewServer(sessionStore, keyManager, cookieManager, "issuer", "audience", 3600)

	req := &stsv1.ExchangeRequest{
		SessionCookie: "valid-cookie",
	}

	_, err := server.ExchangeSession(ctx, req)

	if err == nil {
		t.Fatal("Expected error for token minting failure")
	}

	if err.Error() != "rpc error: code = Internal desc = failed to mint token" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestRevokeUserSessions_Success(t *testing.T) {
	ctx := context.Background()

	sessionStore := &MockSessionStore{
		revokeUserSessionsFunc: func(ctx context.Context, userID string) error {
			if userID == "user-456" {
				return nil // Success
			}
			return errors.New("user not found")
		},
	}

	server := NewServer(sessionStore, &MockKeyManager{}, &MockCookieManager{}, "issuer", "audience", 3600)

	req := &stsv1.RevokeUserRequest{
		UserId: "user-456",
	}

	resp, err := server.RevokeUserSessions(ctx, req)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !resp.Success {
		t.Error("Expected success to be true")
	}
}

func TestRevokeUserSessions_EmptyUserId(t *testing.T) {
	ctx := context.Background()

	server := NewServer(&MockSessionStore{}, &MockKeyManager{}, &MockCookieManager{}, "issuer", "audience", 3600)

	req := &stsv1.RevokeUserRequest{
		UserId: "",
	}

	_, err := server.RevokeUserSessions(ctx, req)

	if err == nil {
		t.Fatal("Expected error for empty user_id")
	}

	if err.Error() != "rpc error: code = InvalidArgument desc = user_id is required" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestRevokeUserSessions_Failure(t *testing.T) {
	ctx := context.Background()

	sessionStore := &MockSessionStore{
		revokeUserSessionsFunc: func(ctx context.Context, userID string) error {
			return errors.New("database error")
		},
	}

	server := NewServer(sessionStore, &MockKeyManager{}, &MockCookieManager{}, "issuer", "audience", 3600)

	req := &stsv1.RevokeUserRequest{
		UserId: "user-456",
	}

	resp, err := server.RevokeUserSessions(ctx, req)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if resp.Success {
		t.Error("Expected success to be false when revocation fails")
	}
}

func TestNewServer(t *testing.T) {
	sessionStore := &MockSessionStore{}
	keyManager := &MockKeyManager{}
	cookieManager := &MockCookieManager{}

	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 7200)

	if server == nil {
		t.Fatal("Expected server to be initialized")
	}

	if server.jwtIssuer != "test-issuer" {
		t.Errorf("Expected issuer 'test-issuer', got: %s", server.jwtIssuer)
	}

	if server.jwtAudience != "test-audience" {
		t.Errorf("Expected audience 'test-audience', got: %s", server.jwtAudience)
	}

	if server.jwtExpiry != 7200 {
		t.Errorf("Expected expiry 7200, got: %d", server.jwtExpiry)
	}
}
