// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package grpcserver

//go:generate mockgen -build_flags=--mod=mod -package grpcserver -destination ./mock_interfaces.go -source=./interfaces.go

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	stsv1 "github.com/canonical/secure-token-service/api/proto/v1"
	"github.com/canonical/secure-token-service/internal/auth"
	"github.com/canonical/secure-token-service/internal/observability"
	"github.com/canonical/secure-token-service/internal/session"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil, WithSessionExpiry(24*time.Hour))

	// Setup mock expectations
	cookieManager.EXPECT().
		Decode("session_id", "test-cookie-value", 86400).
		Return("session-123", nil)

	sessionStore.EXPECT().
		Get(ctx, "session-123").
		Return(&session.Session{
			SessionID: "session-123",
			UserID:    "user-456",
			Provider:  "oidc",
			Claims: map[string]interface{}{
				"sub":   "user-456",
				"email": "user@example.com",
			},
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

// TestExchangeSession_DefaultSessionMaxAge tests that cookie age is limited by default.
func TestExchangeSession_DefaultSessionMaxAge(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cookieManager := NewMockCookieManager(ctrl)
	server := NewServer(NewMockSessionStore(ctrl), NewMockKeyManager(ctrl), cookieManager, "test-issuer", "test-audience", 3600, nil)

	cookieManager.EXPECT().
		Decode("session_id", "expired-cookie", 86400).
		Return("", errors.New("expired"))

	_, err := server.ExchangeSession(context.Background(), &stsv1.ExchangeRequest{SessionCookie: "expired-cookie"})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got: %v", err)
	}
}

// TestExchangeSession_WithOpenIDClaims tests that session claims are forwarded to MintToken
func TestExchangeSession_WithOpenIDClaims(t *testing.T) {
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
		Decode("session_id", "openid-cookie", gomock.Any()).
		Return("session-openid-123", nil)

	sessionStore.EXPECT().
		Get(ctx, "session-openid-123").
		Return(&session.Session{
			SessionID: "session-openid-123",
			UserID:    "Xb6LTdm",
			Provider:  "openid",
			Claims: map[string]interface{}{
				"sub":          "spoofed-openid-sub",
				"claimed_id":   "https://login.ubuntu.com/+id/Xb6LTdm",
				"nickname":     "testuser",
				"name":         "Test User",
				"idp_provider": "openid",
				"email":        "user@example.com",
				"u1_sso_id":    "Xb6LTdm",
			},
		}, nil)

	expectedClaims := map[string]interface{}{
		"email":        "user@example.com",
		"u1_sso_id":    "Xb6LTdm",
		"nickname":     "testuser",
		"name":         "Test User",
		"idp_provider": "openid",
	}
	keyManager.EXPECT().
		MintToken("", "test-issuer", "test-audience", 3600, expectedClaims).
		Return("mock-jwt-token-openid", nil)

	// Execute test
	req := &stsv1.ExchangeRequest{
		SessionCookie: "openid-cookie",
	}

	resp, err := server.ExchangeSession(ctx, req)

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if resp.AccessToken != "mock-jwt-token-openid" {
		t.Errorf("Expected token 'mock-jwt-token-openid', got: %s", resp.AccessToken)
	}

	if resp.ExpiresIn != 3600 {
		t.Errorf("Expected expiry 3600, got: %d", resp.ExpiresIn)
	}
}

func TestExchangeSession_WithOIDCProfileAndTenantClaims(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)

	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil)

	cookieManager.EXPECT().
		Decode("session_id", "oidc-cookie", gomock.Any()).
		Return("session-oidc-123", nil)

	sessionStore.EXPECT().
		Get(ctx, "session-oidc-123").
		Return(&session.Session{
			SessionID: "session-oidc-123",
			UserID:    "oidc-sub-1",
			Provider:  "oidc",
			Claims: map[string]interface{}{
				"sub":          "oidc-sub-1",
				"email":        "alice@canonical.com",
				"u1_sso_id":    "Xb6LTdm",
				"name":         "Alice Smith",
				"given_name":   "Alice",
				"tenant":       "canonical",
				"idp_provider": "oidc",
			},
		}, nil)

	expectedClaims := map[string]interface{}{
		"sub":          "oidc-sub-1",
		"email":        "alice@canonical.com",
		"u1_sso_id":    "Xb6LTdm",
		"name":         "Alice Smith",
		"given_name":   "Alice",
		"tenant":       "canonical",
		"idp_provider": "oidc",
	}

	keyManager.EXPECT().
		MintToken("oidc-sub-1", "test-issuer", "test-audience", 3600, expectedClaims).
		Return("mock-jwt-token-oidc", nil)

	resp, err := server.ExchangeSession(ctx, &stsv1.ExchangeRequest{
		SessionCookie: "oidc-cookie",
	})
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp.AccessToken != "mock-jwt-token-oidc" {
		t.Errorf("Expected token 'mock-jwt-token-oidc', got: %s", resp.AccessToken)
	}
}

func TestExchangeSession_OmitsEmailWhenNoEmailPresent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)

	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil)

	cookieManager.EXPECT().
		Decode("session_id", "unverified-cookie", gomock.Any()).
		Return("session-unverified-123", nil)

	sessionStore.EXPECT().
		Get(ctx, "session-unverified-123").
		Return(&session.Session{
			SessionID: "session-unverified-123",
			UserID:    "oidc-sub-999",
			Provider:  "oidc",
			Claims: map[string]interface{}{
				"email":        "alice@canonical.com",
				"u1_sso_id":    "   ",
				"sub":          "oidc-sub-999",
				"name":         "No U1 User",
				"idp_provider": "oidc",
			},
		}, nil)

	expectedClaims := map[string]interface{}{
		"sub":          "oidc-sub-999",
		"email":        "alice@canonical.com",
		"name":         "No U1 User",
		"idp_provider": "oidc",
	}

	keyManager.EXPECT().
		MintToken("oidc-sub-999", "test-issuer", "test-audience", 3600, expectedClaims).
		Return("mock-jwt-token-no-email", nil)
	resp, err := server.ExchangeSession(ctx, &stsv1.ExchangeRequest{
		SessionCookie: "unverified-cookie",
	})
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp.AccessToken != "mock-jwt-token-no-email" {
		t.Errorf("Expected token 'mock-jwt-token-no-email', got: %s", resp.AccessToken)
	}
}

func TestExchangeSession_RejectsLegacyAndInconsistentSessions(t *testing.T) {
	tests := []struct {
		name string
		sess *session.Session
	}{
		{
			name: "legacy OpenID session without u1_sso_id",
			sess: &session.Session{
				SessionID: "legacy-openid",
				UserID:    "alice@canonical.com",
				Provider:  "openid",
				Claims: map[string]interface{}{
					"email":      "alice@canonical.com",
					"claimed_id": "https://login.ubuntu.com/+id/Xb6LTdm",
				},
			},
		},
		{
			name: "OpenID session with blank u1_sso_id",
			sess: &session.Session{
				SessionID: "blank-u1",
				UserID:    "https://login.ubuntu.com/+id/Xb6LTdm",
				Provider:  "openid",
				Claims: map[string]interface{}{
					"email":     "alice@canonical.com",
					"u1_sso_id": "   ",
				},
			},
		},
		{
			name: "legacy OIDC session with email UserID and distinct sub claim",
			sess: &session.Session{
				SessionID: "legacy-oidc",
				UserID:    "alice@canonical.com",
				Provider:  "oidc",
				Claims: map[string]interface{}{
					"sub":   "oidc-sub-1",
					"email": "alice@canonical.com",
				},
			},
		},
		{
			name: "non-OpenID session with empty UserID",
			sess: &session.Session{
				SessionID: "empty-uid",
				UserID:    "   ",
				Provider:  "oidc",
				Claims: map[string]interface{}{
					"email": "alice@canonical.com",
				},
			},
		},
		{
			name: "claimless legacy OIDC session rejected",
			sess: &session.Session{
				SessionID: "legacy-claimless-oidc",
				UserID:    "alice@canonical.com",
				Provider:  "oidc",
			},
		},
		{
			name: "empty provider session rejected",
			sess: &session.Session{
				SessionID: "empty-provider",
				UserID:    "user-1",
			},
		},
		{
			name: "OpenID session with full URL u1_sso_id rejected",
			sess: &session.Session{
				SessionID: "url-u1-openid",
				UserID:    "https://login.ubuntu.com/+id/Xb6LTdm",
				Provider:  "openid",
				Claims: map[string]interface{}{
					"email":     "alice@canonical.com",
					"u1_sso_id": "https://login.ubuntu.com/+id/Xb6LTdm",
				},
			},
		},
		{
			name: "OIDC session with whitespace email rejected",
			sess: &session.Session{
				SessionID: "blank-email-oidc",
				UserID:    "oidc-sub-999",
				Provider:  "oidc",
				Claims: map[string]interface{}{
					"sub":   "oidc-sub-999",
					"email": "   ",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			cookieManager := NewMockCookieManager(ctrl)
			sessionStore := NewMockSessionStore(ctrl)
			keyManager := NewMockKeyManager(ctrl)
			server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil)

			cookieManager.EXPECT().Decode("session_id", "cookie-val", gomock.Any()).Return(tc.sess.SessionID, nil)
			sessionStore.EXPECT().Get(gomock.Any(), tc.sess.SessionID).Return(tc.sess, nil)

			_, err := server.ExchangeSession(context.Background(), &stsv1.ExchangeRequest{SessionCookie: "cookie-val"})
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("status = %v, want Unauthenticated", status.Code(err))
			}
		})
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
		{"invalid subject", auth.ErrInvalidSubject, codes.InvalidArgument},
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

// TestExchangeToken_OversizedToken tests that tokens exceeding MaxTokenSizeBytes are rejected
func TestExchangeToken_OversizedToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)
	tokenVerifier := NewMockTokenVerifier(ctrl)

	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil, WithTokenVerifier(tokenVerifier))

	oversizedToken := strings.Repeat("a", MaxTokenSizeBytes+1)
	req := &stsv1.ExchangeTokenRequest{Token: oversizedToken}

	_, err := server.ExchangeToken(ctx, req)
	if err == nil {
		t.Fatal("expected error for oversized token, got nil")
	}

	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

type mockCloserVerifier struct {
	*MockTokenVerifier
	closed bool
}

func (m *mockCloserVerifier) Close() error {
	m.closed = true
	return nil
}

// TestServer_Stop_ClosesVerifier verifies that Server.Stop() closes the token verifier if it implements io.Closer
func TestServer_Stop_ClosesVerifier(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)
	baseVerifier := NewMockTokenVerifier(ctrl)
	closerVerifier := &mockCloserVerifier{MockTokenVerifier: baseVerifier}

	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 3600, nil, WithTokenVerifier(closerVerifier))

	server.Stop()
	if !closerVerifier.closed {
		t.Errorf("expected closerVerifier.Close() to have been called on Stop()")
	}
}

// TestExchangeToken_SecurityAuditLogging verifies structured Zap audit logging on token exchange
func TestExchangeToken_SecurityAuditLogging(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)
	tokenVerifier := NewMockTokenVerifier(ctrl)

	var logBuf bytes.Buffer
	encCfg := zap.NewProductionEncoderConfig()
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encCfg),
		zapcore.AddSync(&logBuf),
		zap.InfoLevel,
	)
	obsLogger := zap.New(core)
	obs := &observability.Observability{
		Logger: &observability.Logger{Logger: obsLogger},
	}

	server := NewServer(sessionStore, keyManager, cookieManager, "test-issuer", "test-audience", 1800, obs, WithTokenVerifier(tokenVerifier))

	rawToken := "secret-upstream-token-do-not-log"
	upstreamExp := time.Now().Add(3600 * time.Second)

	tokenVerifier.EXPECT().
		Verify(ctx, rawToken).
		Return(&auth.VerifiedToken{
			Subject:   "audit-client",
			ClientID:  "audit-client",
			ExpiresAt: upstreamExp,
			Claims:    map[string]interface{}{},
		}, nil)

	keyManager.EXPECT().
		MintToken("audit-client", "test-issuer", "test-audience", 1800, gomock.Any()).
		Return("minted-sts-jwt", nil)

	req := &stsv1.ExchangeTokenRequest{Token: rawToken}
	_, err := server.ExchangeToken(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify structured audit log entry in JSON buffer
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, `"event":"sts.m2m.token_exchange"`) {
		t.Errorf("expected event 'sts.m2m.token_exchange' in logs, got %s", logOutput)
	}
	if !strings.Contains(logOutput, `"outcome":"success"`) {
		t.Errorf("expected outcome 'success' in logs, got %s", logOutput)
	}
	if !strings.Contains(logOutput, `"grpc_code":"OK"`) {
		t.Errorf("expected grpc_code 'OK' in logs, got %s", logOutput)
	}
	if !strings.Contains(logOutput, `"client_id":"audit-client"`) {
		t.Errorf("expected client_id 'audit-client' in logs, got %s", logOutput)
	}
	if !strings.Contains(logOutput, `"clamped_ttl_seconds":1800`) {
		t.Errorf("expected clamped_ttl_seconds 1800 in logs, got %s", logOutput)
	}

	// Verify raw token is never leaked in log output
	if strings.Contains(logOutput, rawToken) {
		t.Errorf("raw token leaked in log output: %s", logOutput)
	}

	// Verify log line can be unmarshaled as valid JSON
	var logEntry map[string]interface{}
	err = json.Unmarshal([]byte(strings.TrimSpace(logOutput)), &logEntry)
	if err != nil {
		t.Fatalf("failed to unmarshal log line as JSON: %v (output: %s)", err, logOutput)
	}
	if logEntry["event"] != "sts.m2m.token_exchange" {
		t.Errorf("expected parsed event 'sts.m2m.token_exchange', got %v", logEntry["event"])
	}
}
