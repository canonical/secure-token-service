// Copyright 2026 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/canonical/secure-token-service/internal/db"
	"github.com/golang-jwt/jwt/v5"
)

type stubJWKSRepo struct {
	keys []*db.JWKSKey
}

func (r *stubJWKSRepo) GetLatestActiveKey(_ context.Context) (*db.JWKSKey, error) {
	for i := len(r.keys) - 1; i >= 0; i-- {
		if r.keys[i].SID == "public" {
			return r.keys[i], nil
		}
	}
	return nil, errors.New("no active key")
}

func (r *stubJWKSRepo) GetAllPublicKeys(_ context.Context) ([]*db.JWKSKey, error) {
	return r.keys, nil
}

func (r *stubJWKSRepo) GetKeyByKID(_ context.Context, kid string) (*db.JWKSKey, error) {
	for _, k := range r.keys {
		if k.KID == kid {
			return k, nil
		}
	}
	return nil, errors.New("not found")
}

func (r *stubJWKSRepo) SaveKey(_ context.Context, key *db.JWKSKey) error {
	r.keys = append(r.keys, key)
	return nil
}

func (r *stubJWKSRepo) RotateKey(_ context.Context, newKey *db.JWKSKey) error {
	for _, k := range r.keys {
		if k.SID == "public" {
			k.SID = "public.retired"
		}
	}
	r.keys = append(r.keys, newKey)
	return nil
}

func (r *stubJWKSRepo) DeleteKey(_ context.Context, sid, kid string) error {
	return nil
}

func TestKeyManager_MintToken_StandardClaimsCannotBeOverwritten(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	km, err := NewKeyManager(ctx, &stubJWKSRepo{}, nil, 0)
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}

	// Simulate OIDC session claims carrying an upstream opaque "sub" alongside other claims.
	customClaims := map[string]interface{}{
		"sub":    "upstream-oidc-opaque-sub",
		"iss":    "https://evil.example.com",
		"aud":    "wrong-audience",
		"iat":    int64(1),
		"exp":    int64(2),
		"email":  "alice@canonical.com",
		"name":   "Alice Smith",
		"tenant": "canonical",
	}

	tokenStr, err := km.MintToken("alice@canonical.com", "sts-issuer", "internal-services", 3600, customClaims)
	if err != nil {
		t.Fatalf("MintToken failed: %v", err)
	}

	pubKey, err := km.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}

	parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("failed to verify minted JWT: %v", err)
	}

	claims := parsed.Claims.(jwt.MapClaims)
	if claims["sub"] != "alice@canonical.com" {
		t.Errorf("sub = %v, want alice@canonical.com", claims["sub"])
	}
	if claims["iss"] != "sts-issuer" {
		t.Errorf("iss = %v, want sts-issuer", claims["iss"])
	}
	if claims["aud"] != "internal-services" {
		t.Errorf("aud = %v, want internal-services", claims["aud"])
	}
	if claims["email"] != "alice@canonical.com" {
		t.Errorf("email = %v, want alice@canonical.com", claims["email"])
	}
	if claims["tenant"] != "canonical" {
		t.Errorf("tenant = %v, want canonical", claims["tenant"])
	}
	iat, ok := claims["iat"].(float64)
	if !ok || int64(iat) <= 1000 {
		t.Errorf("iat = %v, expected current unix timestamp (not overwritten to 1)", claims["iat"])
	}
	exp, ok := claims["exp"].(float64)
	if !ok || int64(exp)-int64(iat) != 3600 {
		t.Errorf("exp = %v, iat = %v, want exp-iat == 3600", claims["exp"], claims["iat"])
	}
}

func TestKeyManager_MintToken_EmptySubjectOmitsSubClaim(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	km, err := NewKeyManager(ctx, &stubJWKSRepo{}, nil, 0)
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}

	customClaims := map[string]interface{}{
		"sub":       "spoofed-sub",
		"email":     "alice@canonical.com",
		"u1_sso_id": "Xb6LTdm",
	}

	tokenStr, err := km.MintToken("", "sts-issuer", "internal-services", 3600, customClaims)
	if err != nil {
		t.Fatalf("MintToken failed: %v", err)
	}

	pubKey, err := km.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}

	parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("failed to verify minted JWT: %v", err)
	}

	claims := parsed.Claims.(jwt.MapClaims)
	if _, exists := claims["sub"]; exists {
		t.Errorf("expected sub claim to be omitted when subject is empty, got %v", claims["sub"])
	}
	if claims["email"] != "alice@canonical.com" {
		t.Errorf("email = %v, want alice@canonical.com", claims["email"])
	}
	if claims["u1_sso_id"] != "Xb6LTdm" {
		t.Errorf("u1_sso_id = %v, want Xb6LTdm", claims["u1_sso_id"])
	}
	if claims["iss"] != "sts-issuer" {
		t.Errorf("iss = %v, want sts-issuer", claims["iss"])
	}
	if claims["aud"] != "internal-services" {
		t.Errorf("aud = %v, want internal-services", claims["aud"])
	}
}
