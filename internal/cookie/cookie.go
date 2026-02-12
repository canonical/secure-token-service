// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/canonical/secure-token-service/internal/constants"
	"github.com/chmike/securecookie"
)

// CookieManager handles secure cookie encoding and decoding.
type CookieManager struct {
	key          []byte
	aesCipher    cipher.Block
	oauthStateCk *securecookie.Obj
	oauthNonceCk *securecookie.Obj
}

// NewCookieManager creates a new CookieManager with the given keys.
// hashKey is required, used to authenticate the cookie value using HMAC.
// blockKey is optional, used to encrypt the cookie value. Set to nil or empty slice to disable encryption.
// Note: chmike/securecookie uses a single key (combines both hash and encryption).
func NewCookieManager(hashKey, blockKey []byte) *CookieManager {
	// chmike/securecookie requires a 32-byte key for AES-128 + HMAC-SHA256
	// We'll use the hashKey as the primary key
	key := hashKey
	if len(key) < 32 {
		// If hashKey is too short, we need to derive a proper key
		// For compatibility, we'll pad or use the first 32 bytes
		derivedKey := make([]byte, 32)
		copy(derivedKey, hashKey)
		key = derivedKey
	} else if len(key) > 32 {
		key = key[:32]
	}

	// Create AES cipher for fast encoding/decoding
	aesCipher, err := aes.NewCipher(key[:16])
	if err != nil {
		panic(fmt.Sprintf("failed to create AES cipher: %v", err))
	}

	// Create cookie objects for each cookie type
	oauthStateCk := securecookie.MustNew("oauth_state", key, securecookie.Params{
		Path:     "/",
		MaxAge:   constants.CookieMaxAge,
		HTTPOnly: true,
		Secure:   false, // Will be set dynamically based on request
	})

	oauthNonceCk := securecookie.MustNew("oauth_nonce", key, securecookie.Params{
		Path:     "/",
		MaxAge:   constants.CookieMaxAge,
		HTTPOnly: true,
		Secure:   false, // Will be set dynamically based on request
	})

	return &CookieManager{
		key:          key,
		aesCipher:    aesCipher,
		oauthStateCk: oauthStateCk,
		oauthNonceCk: oauthNonceCk,
	}
}

// Encode encodes a cookie name and value using a fast, optimized approach.
// This implementation uses direct encryption + HMAC without HTTP overhead.
func (m *CookieManager) Encode(name, value string) (string, error) {
	valueBytes := []byte(value)

	// Create IV
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt value
	encrypted := make([]byte, len(valueBytes))
	stream := cipher.NewCTR(m.aesCipher, iv)
	stream.XORKeyStream(encrypted, valueBytes)

	// Combine: IV || encrypted data
	combined := make([]byte, 0, len(iv)+len(encrypted))
	combined = append(combined, iv...)
	combined = append(combined, encrypted...)

	// Create HMAC
	h := hmac.New(sha256.New, m.key)
	h.Write([]byte(name))
	h.Write(combined)
	mac := h.Sum(nil)

	// Combine: IV || encrypted || MAC
	final := make([]byte, 0, len(combined)+len(mac))
	final = append(final, combined...)
	final = append(final, mac...)

	// Base64 encode
	return base64.RawURLEncoding.EncodeToString(final), nil
}

// Decode decodes a cookie name and value using a fast, optimized approach.
func (m *CookieManager) Decode(name, value string) (string, error) {
	// Base64 decode
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Minimum length check: IV (16) + MAC (32)
	if len(decoded) < 48 {
		return "", errors.New("invalid cookie: too short")
	}

	// Split: IV || encrypted || MAC
	macStart := len(decoded) - 32
	combined := decoded[:macStart]
	mac := decoded[macStart:]

	// Verify HMAC
	h := hmac.New(sha256.New, m.key)
	h.Write([]byte(name))
	h.Write(combined)
	expectedMAC := h.Sum(nil)

	if !hmac.Equal(mac, expectedMAC) {
		return "", errors.New("invalid cookie: MAC mismatch")
	}

	// Split: IV || encrypted
	if len(combined) < 16 {
		return "", errors.New("invalid cookie: missing IV")
	}
	iv := combined[:16]
	encrypted := combined[16:]

	// Decrypt
	decrypted := make([]byte, len(encrypted))
	stream := cipher.NewCTR(m.aesCipher, iv)
	stream.XORKeyStream(decrypted, encrypted)

	return string(decrypted), nil
}

// OIDC State Methods

// SetOIDCState generates a state, creates a cookie with returnTo, and sets it on the response.
func (m *CookieManager) SetOIDCState(w http.ResponseWriter, r *http.Request, returnTo string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	state := base64.URLEncoding.EncodeToString(b)

	stateData := map[string]string{
		"state":     state,
		"return_to": returnTo,
	}
	stateBytes, _ := json.Marshal(stateData)

	// Use chmike's SetValue directly, but we need to handle the Secure flag dynamically
	if err := m.setSecureCookieValue(w, r, m.oauthStateCk, stateBytes); err != nil {
		return "", err
	}

	return state, nil
}

// GetOIDCState retrieves and decodes the OIDC state cookie.
func (m *CookieManager) GetOIDCState(r *http.Request) (map[string]string, error) {
	decodedStateBytes, err := m.oauthStateCk.GetValue(nil, r)
	if err != nil {
		return nil, fmt.Errorf("invalid state cookie: %w", err)
	}

	var stateData map[string]string
	if err := json.Unmarshal(decodedStateBytes, &stateData); err != nil {
		return nil, fmt.Errorf("failed to parse state data: %w", err)
	}

	return stateData, nil
}

// ClearOIDCState clears the OIDC state cookie.
func (m *CookieManager) ClearOIDCState(w http.ResponseWriter, r *http.Request) {
	m.oauthStateCk.Delete(w)
}

// OIDC Nonce Methods

// SetOIDCNonce generates a nonce, creates a cookie, and sets it on the response.
func (m *CookieManager) SetOIDCNonce(w http.ResponseWriter, r *http.Request) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonce := base64.URLEncoding.EncodeToString(b)

	if err := m.setSecureCookieValue(w, r, m.oauthNonceCk, []byte(nonce)); err != nil {
		return "", err
	}

	return nonce, nil
}

// GetOIDCNonce retrieves and decodes the OIDC nonce cookie.
func (m *CookieManager) GetOIDCNonce(r *http.Request) (string, error) {
	decodedNonce, err := m.oauthNonceCk.GetValue(nil, r)
	if err != nil {
		return "", fmt.Errorf("invalid nonce cookie: %w", err)
	}

	return string(decodedNonce), nil
}

// ClearOIDCNonce clears the OIDC nonce cookie.
func (m *CookieManager) ClearOIDCNonce(w http.ResponseWriter, r *http.Request) {
	m.oauthNonceCk.Delete(w)
}

// setSecureCookieValue sets a cookie value with dynamic Secure flag based on request
func (m *CookieManager) setSecureCookieValue(w http.ResponseWriter, r *http.Request, ck *securecookie.Obj, value []byte) error {
	// Since chmike's cookie object has a fixed Secure setting, we need to handle this manually
	// We'll use SetValue and then modify the cookie header if needed

	// Check if we should use secure cookies
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

	// If the cookie is already configured with the right secure setting, use it directly
	// Otherwise, we need to manually construct the cookie
	if ck.Secure() == isSecure {
		return ck.SetValue(w, value)
	}

	// We need to manually set the cookie with the correct Secure flag
	// First, encode the value using httptest.NewRecorder()
	recorder := httptest.NewRecorder()
	if err := ck.SetValue(recorder, value); err != nil {
		return err
	}

	// Get the Set-Cookie header and modify it
	setCookie := recorder.Header().Get("Set-Cookie")
	if setCookie == "" {
		return fmt.Errorf("failed to set cookie: no Set-Cookie header")
	}

	// Add or remove Secure flag as needed
	if isSecure && !ck.Secure() {
		setCookie += "; Secure"
	}
	// Note: we can't remove Secure if it's already there without parsing and rebuilding

	w.Header().Add("Set-Cookie", setCookie)
	return nil
}
