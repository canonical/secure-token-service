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
	"strings"
	"time"

	"github.com/canonical/secure-token-service/internal/constants"
	"github.com/chmike/securecookie"
)

var ErrKeyTooShort = errors.New("cookie key is too short: minimum length is 32 bytes")

const MinKeyLength = 32

// AuthState holds state data across the authentication redirection flow.
type AuthState struct {
	State    string `json:"state"`
	ReturnTo string `json:"return_to"`
	Provider string `json:"provider"`
}

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
		SameSite: securecookie.Lax,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create session cookie: %w", err)
	}

	oauthStateCk, err := securecookie.New("oauth_state", key, securecookie.Params{
		Path:     "/",
		MaxAge:   constants.CookieMaxAge,
		HTTPOnly: true,
		Secure:   false, // Will be set dynamically based on request
		SameSite: securecookie.Lax,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth state cookie: %w", err)
	}

	oauthNonceCk, err := securecookie.New("oauth_nonce", key, securecookie.Params{
		Path:     "/",
		MaxAge:   constants.CookieMaxAge,
		HTTPOnly: true,
		Secure:   false, // Will be set dynamically based on request
		SameSite: securecookie.Lax,
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
		SameSite: securecookie.Lax,
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

// Decode decodes a cookie name and value using securecookie.
func (m *CookieManager) Decode(name, value string) (string, error) {
	// Create a temporary securecookie object for this specific name
	obj, err := securecookie.New(name, m.key, securecookie.Params{
		Path:     "/",
		MaxAge:   constants.CookieMaxAge,
		HTTPOnly: true,
		Secure:   false,
		SameSite: securecookie.Lax,
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

// SetSessionCookie sets a standardized session cookie on the response.
func (m *CookieManager) SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string, expiresAt time.Time) error {
	encodedSession, err := m.Encode("session_id", sessionID)
	if err != nil {
		return fmt.Errorf("failed to encode session cookie: %w", err)
	}

	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    encodedSession,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
	return nil
}

// ClearSessionCookie clears the session cookie on the response with standard security attributes.
func (m *CookieManager) ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	m.deleteSecureCookie(w, r, "session_id")
}

// Auth State Methods

// SetAuthState generates a state if not provided, creates an encrypted cookie with state, returnTo, and provider, and sets it on the response.
func (m *CookieManager) SetAuthState(w http.ResponseWriter, r *http.Request, state AuthState) (string, error) {
	if state.State == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("failed to generate state: %w", err)
		}
		state.State = base64.URLEncoding.EncodeToString(b)
	}
	if state.Provider == "" {
		state.Provider = "oidc"
	}

	stateBytes, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth state: %w", err)
	}

	if err := m.setSecureCookieValue(w, r, m.oauthStateCk, stateBytes); err != nil {
		return "", err
	}

	return state.State, nil
}

// GetAuthState retrieves and decodes the auth state cookie.
func (m *CookieManager) GetAuthState(r *http.Request) (*AuthState, error) {
	decodedStateBytes, err := m.oauthStateCk.GetValue(nil, r)
	if err != nil {
		return nil, fmt.Errorf("invalid state cookie: %w", err)
	}

	var state AuthState
	if err := json.Unmarshal(decodedStateBytes, &state); err != nil {
		return nil, fmt.Errorf("failed to parse auth state: %w", err)
	}
	if state.Provider == "" {
		state.Provider = "oidc"
	}

	return &state, nil
}

// ClearAuthState clears the auth state cookie.
func (m *CookieManager) ClearAuthState(w http.ResponseWriter, r *http.Request) {
	m.deleteSecureCookie(w, r, "oauth_state")
}

// OIDC State Methods (backward-compatible wrappers)

// SetOIDCState generates a state, creates a cookie with returnTo, and sets it on the response.
// Deprecated: Use SetAuthState instead.
func (m *CookieManager) SetOIDCState(w http.ResponseWriter, r *http.Request, returnTo string) (string, error) {
	return m.SetAuthState(w, r, AuthState{
		ReturnTo: returnTo,
		Provider: "oidc",
	})
}

// GetOIDCState retrieves and decodes the OIDC state cookie.
// Deprecated: Use GetAuthState instead.
func (m *CookieManager) GetOIDCState(r *http.Request) (map[string]string, error) {
	state, err := m.GetAuthState(r)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"state":     state.State,
		"return_to": state.ReturnTo,
		"provider":  state.Provider,
	}, nil
}

// ClearOIDCState clears the OIDC state cookie.
// Deprecated: Use ClearAuthState instead.
func (m *CookieManager) ClearOIDCState(w http.ResponseWriter, r *http.Request) {
	m.ClearAuthState(w, r)
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
	m.deleteSecureCookie(w, r, "oauth_nonce")
}

// isSecureRequest checks whether the request arrived over TLS or behind a TLS-terminating proxy.
func isSecureRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// deleteSecureCookie expires a cookie on the response with standard security attributes.
func (m *CookieManager) deleteSecureCookie(w http.ResponseWriter, r *http.Request, name string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

// setSecureCookieValue sets a cookie value with dynamic Secure flag based on request
func (m *CookieManager) setSecureCookieValue(w http.ResponseWriter, r *http.Request, ck *securecookie.Obj, value []byte) error {
	isSecure := isSecureRequest(r)

	// If the cookie is already configured with the right secure setting, use it directly
	if ck.Secure() == isSecure {
		return ck.SetValue(w, value)
	}

	// We need to manually set the cookie with the correct Secure flag
	// First, encode the value using httptest.NewRecorder()
	recorder := httptest.NewRecorder()
	if err := ck.SetValue(recorder, value); err != nil {
		return err
	}

	setCookie := recorder.Header().Get("Set-Cookie")
	if setCookie == "" {
		return fmt.Errorf("failed to set cookie: no Set-Cookie header")
	}

	if isSecure && !ck.Secure() {
		setCookie += "; Secure"
	}

	w.Header().Add("Set-Cookie", setCookie)
	return nil
}
