// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package grpcserver

//go:generate mockgen -build_flags=--mod=mod -package grpcserver -destination ./mock_interfaces.go -source=./interfaces.go

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	stsv1 "github.com/canonical/secure-token-service/api/proto/v1"
	"github.com/canonical/secure-token-service/internal/auth"
	"github.com/canonical/secure-token-service/internal/session"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	tokenVerifier := NewMockTokenVerifier(ctrl)

	server := NewServer(sessionStore, keyManager, cookieManager, "my-issuer", "my-audience", 7200, nil, WithTokenVerifier(tokenVerifier))

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

	if server.tokenVerifier != tokenVerifier {
		t.Error("Expected tokenVerifier to be configured on server")
	}
}

// TestExchangeToken_Success tests successful exchange of an IdP token
func TestExchangeToken_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)
	tokenVerifier := NewMockTokenVerifier(ctrl)

	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 1800, nil, WithTokenVerifier(tokenVerifier))

	rawToken := "valid-upstream-token"
	upstreamExp := time.Now().Add(3600 * time.Second) // Upstream has 3600s, server config is 1800s -> clamped to 1800s

	tokenVerifier.EXPECT().
		Verify(ctx, rawToken).
		Return(&auth.VerifiedToken{
			Subject:   "client-app-1",
			ClientID:  "client-app-1",
			ExpiresAt: upstreamExp,
			Claims: map[string]interface{}{
				"client_id": "client-app-1",
				"scope":     "read write",
			},
		}, nil)

	expectedClaims := map[string]interface{}{
		"sub":       "client-app-1",
		"client_id": "client-app-1",
		"email":     "client-app-1@serviceaccount.local",
		"scope":     "read write",
	}

	keyManager.EXPECT().
		MintToken("client-app-1", "test-issuer", "test-audience", 1800, expectedClaims).
		Return("minted-sts-jwt", nil)

	req := &stsv1.ExchangeTokenRequest{Token: rawToken}
	resp, err := server.ExchangeToken(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if resp.AccessToken != "minted-sts-jwt" {
		t.Errorf("expected access_token 'minted-sts-jwt', got %s", resp.AccessToken)
	}
	if resp.ExpiresIn != 1800 {
		t.Errorf("expected expiresIn 1800, got %d", resp.ExpiresIn)
	}
}

// TestExchangeToken_ClampingApplied tests that TTL is clamped to remaining upstream validity
func TestExchangeToken_ClampingApplied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)
	tokenVerifier := NewMockTokenVerifier(ctrl)

	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil, WithTokenVerifier(tokenVerifier))

	rawToken := "clamped-upstream-token"
	upstreamExp := time.Now().Add(500 * time.Second) // Less than configured 3600s

	tokenVerifier.EXPECT().
		Verify(ctx, rawToken).
		Return(&auth.VerifiedToken{
			Subject:   "client-app-2",
			ClientID:  "client-app-2",
			ExpiresAt: upstreamExp,
			Claims:    map[string]interface{}{},
		}, nil)

	keyManager.EXPECT().
		MintToken(gomock.Eq("client-app-2"), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(sub, iss, aud string, expiry int, claims map[string]interface{}) (string, error) {
			if expiry > 500 || expiry < 498 {
				return "", fmt.Errorf("expected clamped expiry around 500s, got %d", expiry)
			}
			if claims["email"] != "client-app-2@serviceaccount.local" {
				return "", fmt.Errorf("expected synthetic email, got %v", claims["email"])
			}
			return "clamped-jwt", nil
		})

	req := &stsv1.ExchangeTokenRequest{Token: rawToken}
	resp, err := server.ExchangeToken(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if resp.AccessToken != "clamped-jwt" {
		t.Errorf("expected access_token 'clamped-jwt', got %s", resp.AccessToken)
	}
	if resp.ExpiresIn > 500 || resp.ExpiresIn < 498 {
		t.Errorf("expected clamped expiresIn around 500s, got %d", resp.ExpiresIn)
	}
}

// TestExchangeToken_ExpiringSoonRejected tests that tokens with < 60s remaining are rejected
func TestExchangeToken_ExpiringSoonRejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)
	tokenVerifier := NewMockTokenVerifier(ctrl)

	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil, WithTokenVerifier(tokenVerifier))

	rawToken := "near-expired-token"

	tokenVerifier.EXPECT().
		Verify(ctx, rawToken).
		Return(nil, auth.ErrTokenExpiringSoon)

	req := &stsv1.ExchangeTokenRequest{Token: rawToken}
	_, err := server.ExchangeToken(ctx, req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated status, got %v", err)
	}
}

// TestExchangeToken_MissingToken tests validation when token is empty
func TestExchangeToken_MissingToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)
	tokenVerifier := NewMockTokenVerifier(ctrl)

	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil, WithTokenVerifier(tokenVerifier))

	testCases := []struct {
		name string
		req  *stsv1.ExchangeTokenRequest
	}{
		{"nil request", nil},
		{"empty token", &stsv1.ExchangeTokenRequest{Token: ""}},
		{"whitespace token", &stsv1.ExchangeTokenRequest{Token: "   "}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := server.ExchangeToken(ctx, tc.req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			st, ok := status.FromError(err)
			if !ok || st.Code() != codes.InvalidArgument {
				t.Errorf("expected InvalidArgument, got %v", err)
			}
		})
	}
}

// TestExchangeToken_UnimplementedWithoutVerifier tests behavior when verifier is not configured
func TestExchangeToken_UnimplementedWithoutVerifier(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)

	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil)

	req := &stsv1.ExchangeTokenRequest{Token: "some-token"}
	_, err := server.ExchangeToken(ctx, req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %v", err)
	}
}

// TestExchangeToken_VerifierErrors tests error propagation from verifier
func TestExchangeToken_VerifierErrors(t *testing.T) {
	testCases := []struct {
		name         string
		verifierErr  error
		expectedCode codes.Code
	}{
		{"expired", auth.ErrTokenExpired, codes.Unauthenticated},
		{"invalid signature", auth.ErrInvalidSignature, codes.Unauthenticated},
		{"missing subject", auth.ErrMissingSubject, codes.InvalidArgument},
		{"jwks unavailable", auth.ErrJWKSUnavailable, codes.Unavailable},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ctx := context.Background()
			cookieManager := NewMockCookieManager(ctrl)
			sessionStore := NewMockSessionStore(ctrl)
			keyManager := NewMockKeyManager(ctrl)
			tokenVerifier := NewMockTokenVerifier(ctrl)

			server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil, WithTokenVerifier(tokenVerifier))

			tokenVerifier.EXPECT().
				Verify(ctx, "mock-token").
				Return(nil, tc.verifierErr)

			req := &stsv1.ExchangeTokenRequest{Token: "mock-token"}
			_, err := server.ExchangeToken(ctx, req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			st, ok := status.FromError(err)
			if !ok || st.Code() != tc.expectedCode {
				t.Errorf("expected code %v, got %v (err: %v)", tc.expectedCode, st.Code(), err)
			}
		})
	}
}

// TestExchangeToken_MintTokenError tests internal error when key manager fails
func TestExchangeToken_MintTokenError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)
	tokenVerifier := NewMockTokenVerifier(ctrl)

	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil, WithTokenVerifier(tokenVerifier))

	tokenVerifier.EXPECT().
		Verify(ctx, "valid-token").
		Return(&auth.VerifiedToken{
			Subject:   "client-err",
			ClientID:  "client-err",
			ExpiresAt: time.Now().Add(600 * time.Second),
		}, nil)

	keyManager.EXPECT().
		MintToken("client-err", "test-issuer", "test-audience", gomock.Any(), gomock.Any()).
		Return("", errors.New("key store failure"))

	req := &stsv1.ExchangeTokenRequest{Token: "valid-token"}
	_, err := server.ExchangeToken(ctx, req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Internal {
		t.Errorf("expected Internal error, got %v", err)
	}
}
