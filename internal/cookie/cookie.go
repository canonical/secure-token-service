// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package cookie

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

// CookieManager handles secure cookie encoding and decoding.
type CookieManager struct {
	sc *securecookie.SecureCookie
}

// NewCookieManager creates a new CookieManager with the given keys.
// hashKey is required, used to authenticate the cookie value using HMAC.
// blockKey is optional, used to encrypt the cookie value. Set to nil or empty slice to disable encryption.
func NewCookieManager(hashKey, blockKey []byte) *CookieManager {
	return &CookieManager{
		sc: securecookie.New(hashKey, blockKey),
	}
}

// Encode encodes a cookie name and value.
func (m *CookieManager) Encode(name, value string) (string, error) {
	encoded, err := m.sc.Encode(name, value)
	if err != nil {
		return "", fmt.Errorf("failed to encode cookie: %w", err)
	}
	return encoded, nil
}

// Decode decodes a cookie name and value.
func (m *CookieManager) Decode(name, value string) (string, error) {
	var decoded string
	if err := m.sc.Decode(name, value, &decoded); err != nil {
		return "", fmt.Errorf("failed to decode cookie: %w", err)
	}
	return decoded, nil
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

	encodedState, err := m.Encode("oauth_state", string(stateBytes))
	if err != nil {
		return "", err
	}

	m.setSecureCookie(w, r, "oauth_state", encodedState, 10*time.Minute)
	return state, nil
}

// GetOIDCState retrieves and decodes the OIDC state cookie.
func (m *CookieManager) GetOIDCState(r *http.Request) (map[string]string, error) {
	cookie, err := r.Cookie("oauth_state")
	if err != nil {
		return nil, fmt.Errorf("missing state cookie")
	}

	decodedStateStr, err := m.Decode("oauth_state", cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("invalid state cookie: %w", err)
	}

	var stateData map[string]string
	if err := json.Unmarshal([]byte(decodedStateStr), &stateData); err != nil {
		return nil, fmt.Errorf("failed to parse state data: %w", err)
	}

	return stateData, nil
}

// ClearOIDCState clears the OIDC state cookie.
func (m *CookieManager) ClearOIDCState(w http.ResponseWriter, r *http.Request) {
	m.setSecureCookie(w, r, "oauth_state", "", -1*time.Second)
}

// OIDC Nonce Methods

// SetOIDCNonce generates a nonce, creates a cookie, and sets it on the response.
func (m *CookieManager) SetOIDCNonce(w http.ResponseWriter, r *http.Request) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonce := base64.URLEncoding.EncodeToString(b)

	encodedNonce, err := m.Encode("oauth_nonce", nonce)
	if err != nil {
		return "", err
	}

	m.setSecureCookie(w, r, "oauth_nonce", encodedNonce, 10*time.Minute)
	return nonce, nil
}

// GetOIDCNonce retrieves and decodes the OIDC nonce cookie.
func (m *CookieManager) GetOIDCNonce(r *http.Request) (string, error) {
	cookie, err := r.Cookie("oauth_nonce")
	if err != nil {
		return "", fmt.Errorf("missing nonce cookie")
	}

	decodedNonce, err := m.Decode("oauth_nonce", cookie.Value)
	if err != nil {
		return "", fmt.Errorf("invalid nonce cookie: %w", err)
	}

	return decodedNonce, nil
}

// ClearOIDCNonce clears the OIDC nonce cookie.
func (m *CookieManager) ClearOIDCNonce(w http.ResponseWriter, r *http.Request) {
	m.setSecureCookie(w, r, "oauth_nonce", "", -1*time.Second)
}

func (m *CookieManager) setSecureCookie(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	}

	if ttl < 0 {
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(0, 0)
	} else {
		cookie.Expires = time.Now().Add(ttl)
	}

	http.SetCookie(w, cookie)
}
