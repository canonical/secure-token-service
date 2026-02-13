// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package cookie

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/canonical/secure-token-service/internal/constants"
	"github.com/chmike/securecookie"
	"crypto/rand"
	"encoding/base64"
)

// CookieManager handles secure cookie encoding and decoding.
type CookieManager struct {
	key          []byte
	sessionCk    *securecookie.Obj
	oauthStateCk *securecookie.Obj
	oauthNonceCk *securecookie.Obj
}

// NewCookieManager creates a new CookieManager with the given key.
// key must be 32 bytes for ChaCha20-Poly1305 AEAD encryption used by chmike/securecookie.
func NewCookieManager(key []byte) *CookieManager {
	// chmike/securecookie requires a 32-byte key for ChaCha20-Poly1305
	if len(key) < 32 {
		// If key is too short, pad it to 32 bytes
		derivedKey := make([]byte, 32)
		copy(derivedKey, key)
		key = derivedKey
	} else if len(key) > 32 {
		key = key[:32]
	}

	// Create cookie objects for each cookie type
	sessionCk := securecookie.MustNew("session_id", key, securecookie.Params{
		Path:     "/",
		MaxAge:   constants.CookieMaxAge,
		HTTPOnly: true,
		Secure:   false, // Will be set dynamically based on request
		SameSite: int(http.SameSiteLaxMode),
	})

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
		sessionCk:    sessionCk,
		oauthStateCk: oauthStateCk,
		oauthNonceCk: oauthNonceCk,
	}
}

// getCookieObject returns the appropriate cookie object based on the cookie name.
// For unknown names, it defaults to sessionCk to maintain backward compatibility
// and avoid breaking existing code that may use custom cookie names.
func (m *CookieManager) getCookieObject(name string) *securecookie.Obj {
	switch name {
	case "session_id":
		return m.sessionCk
	case "oauth_state":
		return m.oauthStateCk
	case "oauth_nonce":
		return m.oauthNonceCk
	default:
		// Default to session cookie for unknown names
		return m.sessionCk
	}
}

// Encode encodes a cookie name and value using chmike/securecookie.
// This uses ChaCha20-Poly1305 AEAD for authenticated encryption.
func (m *CookieManager) Encode(name, value string) (string, error) {
	ck := m.getCookieObject(name)

	// Use httptest.NewRecorder() to capture the cookie value
	recorder := httptest.NewRecorder()
	if err := ck.SetValue(recorder, []byte(value)); err != nil {
		return "", fmt.Errorf("failed to encode cookie: %w", err)
	}

	// Extract the cookie value from Set-Cookie header
	setCookie := recorder.Header().Get("Set-Cookie")
	if setCookie == "" {
		return "", errors.New("failed to encode cookie: no Set-Cookie header")
	}

	// Parse the cookie to extract just the value
	cookies := recorder.Result().Cookies()
	if len(cookies) == 0 {
		return "", errors.New("failed to encode cookie: no cookie found")
	}

	return cookies[0].Value, nil
}

// Decode decodes a cookie name and value using chmike/securecookie.
func (m *CookieManager) Decode(name, value string) (string, error) {
	ck := m.getCookieObject(name)

	// Create a fake request with the cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  name,
		Value: value,
	})

	// Use securecookie to decode
	decodedBytes, err := ck.GetValue(nil, req)
	if err != nil {
		return "", fmt.Errorf("failed to decode cookie: %w", err)
	}

	return string(decodedBytes), nil
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
