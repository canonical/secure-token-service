// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package cookie

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/canonical/secure-token-service/internal/constants"
	"github.com/chmike/securecookie"
)

var ErrKeyTooShort = errors.New("cookie key is too short: minimum length is 32 bytes")

const MinKeyLength = 32

// CookieManager handles secure cookie encoding and decoding.
type CookieManager struct {
	key          []byte
	sessionCk    *securecookie.Obj // Main session cookie
	oauthStateCk *securecookie.Obj
	oauthNonceCk *securecookie.Obj
}

// NewCookieManager creates a new CookieManager with the given keys.
// hashKey is required, used to authenticate the cookie value using HMAC.
// Note: chmike/securecookie uses a single key (combines both hash and encryption).
func NewCookieManager(hashKey []byte) (*CookieManager, error) {
	if len(hashKey) < MinKeyLength {
		return nil, fmt.Errorf("%w (got %d bytes, minimum required is %d)", ErrKeyTooShort, len(hashKey), MinKeyLength)
	}

	key := hashKey
	if len(key) > 32 {
		key = key[:32]
	}

	// Create cookie objects for each cookie type
	sessionCk, err := securecookie.New("session_id", key, securecookie.Params{
		Path:     "/",
		MaxAge:   constants.CookieMaxAge,
		HTTPOnly: true,
		Secure:   false, // Will be set dynamically based on request
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create session cookie: %w", err)
	}

	oauthStateCk, err := securecookie.New("oauth_state", key, securecookie.Params{
		Path:     "/",
		MaxAge:   constants.CookieMaxAge,
		HTTPOnly: true,
		Secure:   false, // Will be set dynamically based on request
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth state cookie: %w", err)
	}

	oauthNonceCk, err := securecookie.New("oauth_nonce", key, securecookie.Params{
		Path:     "/",
		MaxAge:   constants.CookieMaxAge,
		HTTPOnly: true,
		Secure:   false, // Will be set dynamically based on request
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth nonce cookie: %w", err)
	}

	return &CookieManager{
		key:          key,
		sessionCk:    sessionCk,
		oauthStateCk: oauthStateCk,
		oauthNonceCk: oauthNonceCk,
	}, nil
}

// Encode encodes a cookie name and value using securecookie.
func (m *CookieManager) Encode(name string, value string) (string, error) {
	// Create a temporary securecookie object for this specific name
	// We use the same params as the main session cookie
	obj, err := securecookie.New(name, m.key, securecookie.Params{
		Path:     "/",
		MaxAge:   constants.CookieMaxAge,
		HTTPOnly: true,
		Secure:   false,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create cookie object: %w", err)
	}

	recorder := httptest.NewRecorder()
	if err := obj.SetValue(recorder, []byte(value)); err != nil {
		return "", err
	}

	cookies := recorder.Result().Cookies()
	if len(cookies) == 0 {
		return "", fmt.Errorf("no cookie generated")
	}

	return cookies[0].Value, nil
}

// Decode decodes a cookie name and value using a fast, optimized approach.
// Decode decodes a cookie name and value using securecookie.
func (m *CookieManager) Decode(name, value string) (string, error) {
	// Create a temporary securecookie object for this specific name
	obj, err := securecookie.New(name, m.key, securecookie.Params{
		Path:     "/",
		MaxAge:   constants.CookieMaxAge,
		HTTPOnly: true,
		Secure:   false,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create cookie object: %w", err)
	}

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		return "", err
	}
	req.AddCookie(&http.Cookie{
		Name:  name,
		Value: value,
	})

	val, err := obj.GetValue(nil, req)
	if err != nil {
		return "", fmt.Errorf("failed to decode cookie: %w", err)
	}

	return string(val), nil
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
