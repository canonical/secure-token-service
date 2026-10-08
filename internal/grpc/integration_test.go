// Copyright 2026 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package grpcserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	stsv1 "github.com/canonical/secure-token-service/api/proto/v1"
	"github.com/canonical/secure-token-service/internal/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestExchangeToken_EndToEndIntegration tests the full flow:
// - Mock Hydra IdP serving JWKS
// - Real HydraTokenVerifier fetching and caching keys
// - Upstream RS256 token verification
// - Clamped TTL computation
// - ES256 internal JWT minting with synthetic email
// - Validation of the minted JWT claims and signature
func TestExchangeToken_EndToEndIntegration(t *testing.T) {
	ctx := context.Background()

	// 1. Generate RSA key for mock upstream Hydra IdP
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	pubJWK, err := jwk.FromRaw(rsaKey.Public())
	if err != nil {
		t.Fatalf("failed to create JWK from RSA public key: %v", err)
	}
	if err := pubJWK.Set(jwk.KeyIDKey, "hydra-key-1"); err != nil {
		t.Fatalf("failed to set kid: %v", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		t.Fatalf("failed to set alg: %v", err)
	}
	if err := pubJWK.Set(jwk.KeyUsageKey, "sig"); err != nil {
		t.Fatalf("failed to set use: %v", err)
	}

	jwkSet := jwk.NewSet()
	if err := jwkSet.AddKey(pubJWK); err != nil {
		t.Fatalf("failed to add key to set: %v", err)
	}

	jwksBytes, err := json.Marshal(jwkSet)
	if err != nil {
		t.Fatalf("failed to marshal JWKS: %v", err)
	}

	// 2. Mock HTTP server serving Hydra's JWKS
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer ts.Close()

	// 3. Initialize real HydraTokenVerifier pointing to the mock JWKS
	verifier, err := auth.NewHydraTokenVerifier(
		ctx,
		ts.URL,
		auth.WithRefreshInterval(time.Minute),
	)
	if err != nil {
		t.Fatalf("failed to initialize HydraTokenVerifier: %v", err)
	}

	// 4. Generate ECDSA P-256 key for STS internal token minting
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cookieManager := NewMockCookieManager(ctrl)
	sessionStore := NewMockSessionStore(ctrl)
	keyManager := NewMockKeyManager(ctrl)

	// Mock KeyManager minting ES256 JWT using ecKey
	keyManager.EXPECT().
		MintToken(gomock.Any(), "https://sts.example.com", "internal-services", gomock.Any(), gomock.Any()).
		DoAndReturn(func(subject, issuer, audience string, expirySeconds int, claims map[string]interface{}) (string, error) {
			tokenClaims := jwt.MapClaims{
				"sub": subject,
				"iss": issuer,
				"aud": audience,
				"iat": time.Now().Unix(),
				"exp": time.Now().Add(time.Duration(expirySeconds) * time.Second).Unix(),
			}
			for k, v := range claims {
				tokenClaims[k] = v
			}
			token := jwt.NewWithClaims(jwt.SigningMethodES256, tokenClaims)
			token.Header["kid"] = "sts-internal-key-1"
			return token.SignedString(ecKey)
		}).
		AnyTimes()

	// 5. Initialize Server with 3600s configured expiry
	server := NewServer(
		sessionStore,
		keyManager,
		cookieManager,
		"https://sts.example.com",
		"internal-services",
		3600,
		nil,
		WithTokenVerifier(verifier),
	)

	// Helper to mint mock upstream Hydra JWT
	mintHydraToken := func(subject string, exp time.Time, key *rsa.PrivateKey, kid string) string {
		claims := jwt.MapClaims{
			"sub":       subject,
			"client_id": subject,
			"exp":       exp.Unix(),
			"iat":       time.Now().Unix(),
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatalf("failed to sign upstream token: %v", err)
		}
		return signed
	}

	t.Run("successful exchange with clamped TTL and synthetic email", func(t *testing.T) {
		// Upstream token valid for 500 seconds (< 3600s configured expiry)
		upstreamToken := mintHydraToken("client-app-xyz", time.Now().Add(500*time.Second), rsaKey, "hydra-key-1")

		resp, err := server.ExchangeToken(ctx, &stsv1.ExchangeTokenRequest{Token: upstreamToken})
		if err != nil {
			t.Fatalf("ExchangeToken failed: %v", err)
		}

		if resp.AccessToken == "" {
			t.Fatal("expected non-empty access_token")
		}

		// Verify clamped expiry: must be around 500 seconds (not 3600s)
		if resp.ExpiresIn > 500 || resp.ExpiresIn < 490 {
			t.Errorf("expected clamped expires_in ~500s, got %d", resp.ExpiresIn)
		}

		// Parse and verify the minted internal JWT using STS ECDSA public key
		parsedToken, err := jwt.Parse(resp.AccessToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				t.Fatalf("unexpected signing method: %v", token.Header["alg"])
			}
			return &ecKey.PublicKey, nil
		})
		if err != nil {
			t.Fatalf("failed to parse/verify minted JWT: %v", err)
		}

		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		if !ok || !parsedToken.Valid {
			t.Fatal("minted JWT is invalid")
		}

		if sub, _ := claims["sub"].(string); sub != "client-app-xyz" {
			t.Errorf("expected sub 'client-app-xyz', got '%v'", sub)
		}
		if email, _ := claims["email"].(string); email != "client-app-xyz@serviceaccount.local" {
			t.Errorf("expected synthetic email 'client-app-xyz@serviceaccount.local', got '%v'", email)
		}
		if iss, _ := claims["iss"].(string); iss != "https://sts.example.com" {
			t.Errorf("expected iss 'https://sts.example.com', got '%v'", iss)
		}
		if aud, _ := claims["aud"].(string); aud != "internal-services" {
			t.Errorf("expected aud 'internal-services', got '%v'", aud)
		}
	})

	t.Run("rejection of token with remaining validity under 60 seconds", func(t *testing.T) {
		nearExpiredToken := mintHydraToken("client-app-xyz", time.Now().Add(45*time.Second), rsaKey, "hydra-key-1")

		_, err := server.ExchangeToken(ctx, &stsv1.ExchangeTokenRequest{Token: nearExpiredToken})
		if err == nil {
			t.Fatal("expected error for near-expired token, got nil")
		}

		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.Unauthenticated {
			t.Errorf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("rejection of token signed with untrusted key", func(t *testing.T) {
		wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate wrong key: %v", err)
		}
		untrustedToken := mintHydraToken("client-app-xyz", time.Now().Add(600*time.Second), wrongKey, "unknown-kid")

		_, err = server.ExchangeToken(ctx, &stsv1.ExchangeTokenRequest{Token: untrustedToken})
		if err == nil {
			t.Fatal("expected error for untrusted signature, got nil")
		}

		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.Unauthenticated {
			t.Errorf("expected Unauthenticated, got %v", err)
		}
	})
}
