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
	"time"

	"github.com/canonical/secure-token-service/internal/constants"
	securecookie "github.com/chmike/securecookie/v2"
)

var ErrKeyTooShort = errors.New("cookie key is too short: minimum length is 32 bytes")

const MinKeyLength = 32

// SessionCookieName is the browser-visible session cookie name, including the
// "__Host-" prefix mandated by securecookie v2.
const SessionCookieName = "__Host-session_id"

// sessionCookieBaseName is the unprefixed name passed to securecookie.New;
// the library adds the "__Host-" prefix itself.
const sessionCookieBaseName = "session_id"

// headerRecorder is a minimal http.ResponseWriter that records headers in an http.Header map
// without requiring net/http/httptest in production code.
type headerRecorder http.Header

func (h headerRecorder) Header() http.Header         { return http.Header(h) }
func (h headerRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (h headerRecorder) WriteHeader(statusCode int)  {}

// AuthState holds state data across the authentication redirection flow.
type AuthState struct {
	State    string `json:"state"`
	ReturnTo string `json:"return_to"`
	Provider string `json:"provider"`
}

// CookieManager handles secure cookie encoding and decoding.
// securecookie v2 always emits "__Host-"-prefixed cookies with Secure,
// HttpOnly, and Path=/ set, and SameSite=Lax by default.
type CookieManager struct {
	keyStore     *securecookie.KeyStore
	oauthStateCk *securecookie.Obj
	oauthNonceCk *securecookie.Obj
}

// NewCookieManager creates a new CookieManager with the given key.
// The key is the seed for the securecookie v2 key store, which derives
// rotating encryption and authentication keys from it.
func NewCookieManager(hashKey []byte) (*CookieManager, error) {
	if len(hashKey) < MinKeyLength {
		return nil, fmt.Errorf("%w (got %d bytes, minimum required is %d)", ErrKeyTooShort, len(hashKey), MinKeyLength)
	}

	seed := hashKey
	if len(seed) > securecookie.SeedLen {
		seed = seed[:securecookie.SeedLen]
	}

	keyStore, err := securecookie.NewKeyStore(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie key store: %w", err)
	}

	oauthStateCk, err := securecookie.New("oauth_state", keyStore, constants.CookieMaxAge*time.Second, securecookie.WithSameSiteLax())
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth state cookie: %w", err)
	}

	oauthNonceCk, err := securecookie.New("oauth_nonce", keyStore, constants.CookieMaxAge*time.Second, securecookie.WithSameSiteLax())
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth nonce cookie: %w", err)
	}

	return &CookieManager{
		keyStore:     keyStore,
		oauthStateCk: oauthStateCk,
		oauthNonceCk: oauthNonceCk,
	}, nil
}

// Encode encodes a cookie name and value using securecookie.
// The cookie object is created with constants.CookieMaxAge, but only the
// encoded value is used; expiry is enforced in Decode.
func (m *CookieManager) Encode(name string, value string) (string, error) {
	obj, err := securecookie.New(name, m.keyStore, constants.CookieMaxAge*time.Second, securecookie.WithSameSiteLax())
	if err != nil {
		return "", fmt.Errorf("failed to create cookie object: %w", err)
	}

	recorder := make(headerRecorder)
	if err := obj.SetValue(recorder, []byte(value)); err != nil {
		return "", err
	}

	resp := &http.Response{Header: recorder.Header()}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return "", fmt.Errorf("no cookie generated")
	}

	return cookies[0].Value, nil
}

// Decode decodes a cookie name and value using securecookie.
// maxAge is the cookie lifetime in seconds, counted from when it was issued;
// maxAge <= 0 disables the age check (up to the securecookie maximum of 400 days).
func (m *CookieManager) Decode(name, value string, maxAge int) (string, error) {
	maxAgeSec := maxAge
	maxAgeSecCeil := int(securecookie.MaxMaxAge / time.Second)
	if maxAgeSec <= 0 {
		maxAgeSec = maxAgeSecCeil
	}
	if maxAgeSec > maxAgeSecCeil {
		maxAgeSec = maxAgeSecCeil
	}
	if maxAgeSec < 1 {
		maxAgeSec = 1
	}

	obj, err := securecookie.New(name, m.keyStore, time.Duration(maxAgeSec)*time.Second, securecookie.WithSameSiteLax())
	if err != nil {
		return "", fmt.Errorf("failed to create cookie object: %w", err)
	}

	req := &http.Request{Header: make(http.Header)}
	req.AddCookie(&http.Cookie{
		Name:  obj.Name(),
		Value: value,
	})

	val, _, err := obj.Value(nil, req)
	if err != nil {
		return "", fmt.Errorf("failed to decode cookie: %w", err)
	}

	return string(val), nil
}

// SetSessionCookie sets a standardized session cookie on the response.
// The cookie is named "__Host-session_id" with Secure, HttpOnly, Path=/,
// SameSite=Lax, and a Max-Age derived from expiresAt.
func (m *CookieManager) SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string, expiresAt time.Time) error {
	maxAge := time.Until(expiresAt).Truncate(time.Second)
	if maxAge < time.Second {
		maxAge = time.Second
	}
	if maxAge > securecookie.MaxMaxAge {
		maxAge = securecookie.MaxMaxAge
	}
	obj, err := securecookie.New(sessionCookieBaseName, m.keyStore, maxAge, securecookie.WithSameSiteLax())
	if err != nil {
		return fmt.Errorf("failed to create session cookie: %w", err)
	}

	if err := obj.SetValue(w, []byte(sessionID)); err != nil {
		return fmt.Errorf("failed to encode session cookie: %w", err)
	}
	return nil
}

// ClearSessionCookie clears the session cookie on the response with standard security attributes.
func (m *CookieManager) ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	m.deleteSecureCookie(w, sessionCookieBaseName)
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

	if err := m.oauthStateCk.SetValue(w, stateBytes); err != nil {
		return "", fmt.Errorf("failed to set state cookie: %w", err)
	}

	return state.State, nil
}

// GetAuthState retrieves and decodes the auth state cookie.
func (m *CookieManager) GetAuthState(r *http.Request) (*AuthState, error) {
	decodedStateBytes, _, err := m.oauthStateCk.Value(nil, r)
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
	m.deleteSecureCookie(w, "oauth_state")
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

	if err := m.oauthNonceCk.SetValue(w, []byte(nonce)); err != nil {
		return "", fmt.Errorf("failed to set nonce cookie: %w", err)
	}

	return nonce, nil
}

// GetOIDCNonce retrieves and decodes the OIDC nonce cookie.
func (m *CookieManager) GetOIDCNonce(r *http.Request) (string, error) {
	decodedNonce, _, err := m.oauthNonceCk.Value(nil, r)
	if err != nil {
		return "", fmt.Errorf("invalid nonce cookie: %w", err)
	}

	return string(decodedNonce), nil
}

// ClearOIDCNonce clears the OIDC nonce cookie.
func (m *CookieManager) ClearOIDCNonce(w http.ResponseWriter, r *http.Request) {
	m.deleteSecureCookie(w, "oauth_nonce")
}

// deleteSecureCookie expires a cookie on the response with standard security attributes.
func (m *CookieManager) deleteSecureCookie(w http.ResponseWriter, name string) {
	obj, err := securecookie.New(name, m.keyStore, constants.CookieMaxAge*time.Second, securecookie.WithSameSiteLax())
	if err != nil {
		return
	}
	_ = obj.Delete(w)
}
