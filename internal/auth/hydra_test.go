// Copyright 2026 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestJWKS(t *testing.T, keyID string) (*rsa.PrivateKey, string, *httptest.Server, *int32) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubJWK, err := jwk.FromRaw(&privateKey.PublicKey)
	require.NoError(t, err)

	err = pubJWK.Set(jwk.KeyIDKey, keyID)
	require.NoError(t, err)
	err = pubJWK.Set(jwk.AlgorithmKey, "RS256")
	require.NoError(t, err)
	err = pubJWK.Set(jwk.KeyUsageKey, "sig")
	require.NoError(t, err)

	keySet := jwk.NewSet()
	err = keySet.AddKey(pubJWK)
	require.NoError(t, err)

	jwksJSON, err := json.Marshal(keySet)
	require.NoError(t, err)

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))

	return privateKey, server.URL, server, &requestCount
}

func mintTestJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

func TestHydraTokenVerifier_ValidToken(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	privKey, jwksURL, srv, hitCount := setupTestJWKS(t, kid)
	defer srv.Close()

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL, WithRefreshInterval(1*time.Minute))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, atomic.LoadInt32(hitCount), int32(1), "preemptive cache should fetch JWKS on startup")

	claims := jwt.MapClaims{
		"sub":       "machine-client-1",
		"client_id": "machine-client-1",
		"exp":       time.Now().Add(10 * time.Minute).Unix(),
		"iat":       time.Now().Unix(),
		"iss":       "https://hydra.example.com",
	}
	rawToken := mintTestJWT(t, privKey, kid, claims)

	vt, err := verifier.Verify(ctx, rawToken)
	require.NoError(t, err)
	assert.Equal(t, "machine-client-1", vt.Subject)
	assert.Equal(t, "machine-client-1", vt.ClientID)
	assert.False(t, vt.ExpiresAt.IsZero())
	assert.Equal(t, "https://hydra.example.com", vt.Claims["iss"])
}

func TestHydraTokenVerifier_EmptyToken(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	_, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL)
	require.NoError(t, err)

	_, err = verifier.Verify(ctx, "")
	assert.ErrorIs(t, err, ErrEmptyToken)

	_, err = verifier.Verify(ctx, "   ")
	assert.ErrorIs(t, err, ErrEmptyToken)
}

func TestHydraTokenVerifier_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	privKey, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"sub":       "machine-client-1",
		"client_id": "machine-client-1",
		"exp":       time.Now().Add(-5 * time.Minute).Unix(),
		"iat":       time.Now().Add(-10 * time.Minute).Unix(),
	}
	rawToken := mintTestJWT(t, privKey, kid, claims)

	_, err = verifier.Verify(ctx, rawToken)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestHydraTokenVerifier_ExpiringSoon(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	privKey, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL)
	require.NoError(t, err)

	// Token with only 30s remaining lifetime (<60s)
	claims := jwt.MapClaims{
		"sub":       "machine-client-1",
		"client_id": "machine-client-1",
		"exp":       time.Now().Add(30 * time.Second).Unix(),
		"iat":       time.Now().Unix(),
	}
	rawToken := mintTestJWT(t, privKey, kid, claims)

	_, err = verifier.Verify(ctx, rawToken)
	assert.ErrorIs(t, err, ErrTokenExpiringSoon)
}

func TestHydraTokenVerifier_WrongSignature(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	_, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	otherPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"sub":       "machine-client-1",
		"client_id": "machine-client-1",
		"exp":       time.Now().Add(10 * time.Minute).Unix(),
	}
	rawToken := mintTestJWT(t, otherPrivKey, kid, claims)

	_, err = verifier.Verify(ctx, rawToken)
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestHydraTokenVerifier_KeyNotFound(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	privKey, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"sub":       "machine-client-1",
		"client_id": "machine-client-1",
		"exp":       time.Now().Add(10 * time.Minute).Unix(),
	}
	// Sign with unknown kid
	rawToken := mintTestJWT(t, privKey, "unknown-kid", claims)

	_, err = verifier.Verify(ctx, rawToken)
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestHydraTokenVerifier_MissingSubject(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	privKey, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	rawToken := mintTestJWT(t, privKey, kid, claims)

	_, err = verifier.Verify(ctx, rawToken)
	assert.ErrorIs(t, err, ErrMissingSubject)
}

func TestHydraTokenVerifier_FallbackSubjectFromClientID(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	privKey, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"client_id": "fallback-client-id",
		"exp":       time.Now().Add(10 * time.Minute).Unix(),
	}
	rawToken := mintTestJWT(t, privKey, kid, claims)

	vt, err := verifier.Verify(ctx, rawToken)
	require.NoError(t, err)
	assert.Equal(t, "fallback-client-id", vt.Subject)
	assert.Equal(t, "fallback-client-id", vt.ClientID)
}

func TestHydraTokenVerifier_FallbackClientIDFromSub(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	privKey, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"sub": "fallback-sub",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	rawToken := mintTestJWT(t, privKey, kid, claims)

	vt, err := verifier.Verify(ctx, rawToken)
	require.NoError(t, err)
	assert.Equal(t, "fallback-sub", vt.Subject)
	assert.Equal(t, "fallback-sub", vt.ClientID)
}

func TestHydraTokenVerifier_ExpectedIssuer(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	privKey, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	expectedIssuer := "https://hydra.canonical.com"
	verifier, err := NewHydraTokenVerifier(ctx, jwksURL, WithExpectedIssuer(expectedIssuer))
	require.NoError(t, err)

	// Valid issuer
	validClaims := jwt.MapClaims{
		"sub": "machine-client",
		"iss": expectedIssuer,
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	validToken := mintTestJWT(t, privKey, kid, validClaims)
	vt, err := verifier.Verify(ctx, validToken)
	require.NoError(t, err)
	assert.Equal(t, "machine-client", vt.Subject)

	// Wrong issuer
	wrongClaims := jwt.MapClaims{
		"sub": "machine-client",
		"iss": "https://attacker.com",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	wrongToken := mintTestJWT(t, privKey, kid, wrongClaims)
	_, err = verifier.Verify(ctx, wrongToken)
	assert.ErrorIs(t, err, ErrIssuerMismatch)
}

func TestHydraTokenVerifier_StaticKeySet(t *testing.T) {
	ctx := context.Background()
	kid := "static-key-1"
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubJWK, err := jwk.FromRaw(&privKey.PublicKey)
	require.NoError(t, err)
	_ = pubJWK.Set(jwk.KeyIDKey, kid)

	set := jwk.NewSet()
	_ = set.AddKey(pubJWK)

	verifier, err := NewHydraTokenVerifier(ctx, "", WithStaticKeySet(set))
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"sub": "machine-client",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	token := mintTestJWT(t, privKey, kid, claims)
	vt, err := verifier.Verify(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, "machine-client", vt.Subject)
}

func TestHydraTokenVerifier_InvalidSubject_TooLong(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	privKey, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL)
	require.NoError(t, err)
	defer verifier.Close()

	// sub exceeds 256 characters
	claims := jwt.MapClaims{
		"sub": strings.Repeat("a", 257),
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	rawToken := mintTestJWT(t, privKey, kid, claims)

	_, err = verifier.Verify(ctx, rawToken)
	assert.ErrorIs(t, err, ErrInvalidSubject)
}

func TestHydraTokenVerifier_InvalidSubject_ControlCharacters(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	privKey, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL)
	require.NoError(t, err)
	defer verifier.Close()

	testCases := []struct {
		name    string
		subject string
	}{
		{"newline in sub", "client\nid"},
		{"carriage return in sub", "client\rid"},
		{"null byte in sub", "client\x00id"},
		{"tab in sub", "client\tid"},
		{"del character in sub", "client\x7fid"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"sub": tc.subject,
				"exp": time.Now().Add(10 * time.Minute).Unix(),
			}
			rawToken := mintTestJWT(t, privKey, kid, claims)

			_, err := verifier.Verify(ctx, rawToken)
			assert.ErrorIs(t, err, ErrInvalidSubject)
		})
	}
}

func TestHydraTokenVerifier_InvalidSubject_NonStringClaim(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	privKey, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL)
	require.NoError(t, err)
	defer verifier.Close()

	claims := jwt.MapClaims{
		"sub":       12345,
		"client_id": "valid-client",
		"exp":       time.Now().Add(10 * time.Minute).Unix(),
	}
	rawToken := mintTestJWT(t, privKey, kid, claims)

	_, err = verifier.Verify(ctx, rawToken)
	assert.ErrorIs(t, err, ErrInvalidSubject)
}

func TestHydraTokenVerifier_ClockSkewTolerance(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	privKey, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	// Configure 5s clock skew tolerance
	verifier, err := NewHydraTokenVerifier(ctx, jwksURL, WithClockSkewTolerance(5*time.Second))
	require.NoError(t, err)
	defer verifier.Close()

	// Token with nbf 2s in the future (within 5s clock skew tolerance)
	validClaims := jwt.MapClaims{
		"sub": "machine-client",
		"nbf": time.Now().Add(2 * time.Second).Unix(),
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	validToken := mintTestJWT(t, privKey, kid, validClaims)

	vt, err := verifier.Verify(ctx, validToken)
	require.NoError(t, err)
	assert.Equal(t, "machine-client", vt.Subject)

	// Token with nbf 10s in the future (beyond 5s clock skew tolerance)
	futureClaims := jwt.MapClaims{
		"sub": "machine-client",
		"nbf": time.Now().Add(10 * time.Second).Unix(),
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	futureToken := mintTestJWT(t, privKey, kid, futureClaims)

	_, err = verifier.Verify(ctx, futureToken)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSignature) // jwt parser wraps nbf errors in ErrTokenNotValidYet, handled as ErrInvalidSignature
}

func TestHydraTokenVerifier_Close(t *testing.T) {
	ctx := context.Background()
	kid := "test-key-1"
	_, jwksURL, srv, _ := setupTestJWKS(t, kid)
	defer srv.Close()

	verifier, err := NewHydraTokenVerifier(ctx, jwksURL)
	require.NoError(t, err)

	err = verifier.Close()
	assert.NoError(t, err)

	// Calling Close again should be idempotent and safe
	err = verifier.Close()
	assert.NoError(t, err)
}
