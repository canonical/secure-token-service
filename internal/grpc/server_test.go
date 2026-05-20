// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package grpcserver

//go:generate mockgen -build_flags=--mod=mod -package grpcserver -destination ./mock_interfaces.go -source=./interfaces.go

import (
	"context"
	"testing"

	stsv1 "github.com/canonical/secure-token-service/api/proto/v1"
	"github.com/canonical/secure-token-service/internal/session"
	"go.uber.org/mock/gomock"
)

// TestExchangeSession tests the ExchangeSession RPC method
func TestExchangeSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()

	// Create generated mocks
	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)

	// Create server
	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil)

	// Setup mock expectations
	cookieManager.EXPECT().
		Decode("session_id", "test-cookie-value").
		Return("session-123", nil)

	sessionStore.EXPECT().
		Get(ctx, "session-123").
		Return(&session.Session{
			SessionID: "session-123",
			UserID:    "user-456",
		}, nil)

	keyManager.EXPECT().
		MintToken("user-456", "test-issuer", "test-audience", 3600, gomock.Any()).
		Return("mock-jwt-token", nil)

	// Execute test
	req := &stsv1.ExchangeRequest{
		SessionCookie: "test-cookie-value",
	}

	resp, err := server.ExchangeSession(ctx, req)

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if resp.AccessToken != "mock-jwt-token" {
		t.Errorf("Expected token 'mock-jwt-token', got: %s", resp.AccessToken)
	}

	if resp.ExpiresIn != 3600 {
		t.Errorf("Expected expiry 3600, got: %d", resp.ExpiresIn)
	}
}

// TestRevokeUserSessions tests the RevokeUserSessions RPC method
func TestRevokeUserSessions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()

	// Create generated mocks
	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)

	// Create server
	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil)

	// Setup mock expectations
	sessionStore.EXPECT().
		RevokeUserSessions(ctx, "user-123").
		Return(nil)

	// Execute test
	req := &stsv1.RevokeUserRequest{
		UserId: "user-123",
	}

	resp, err := server.RevokeUserSessions(ctx, req)

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !resp.Success {
		t.Error("Expected success to be true")
	}
}

// TestNewServer tests server creation with different configurations
func TestNewServer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)

	server := NewServer(sessionStore, keyManager, cookieManager, "my-issuer", "my-audience", 7200, nil)

	if server == nil {
		t.Fatal("Expected server to be created")
	}

	if server.jwtIssuer != "my-issuer" {
		t.Errorf("Expected issuer 'my-issuer', got: %s", server.jwtIssuer)
	}

	if server.jwtAudience != "my-audience" {
		t.Errorf("Expected audience 'my-audience', got: %s", server.jwtAudience)
	}

	if server.jwtExpiry != 7200 {
		t.Errorf("Expected expiry 7200, got: %d", server.jwtExpiry)
	}
}
