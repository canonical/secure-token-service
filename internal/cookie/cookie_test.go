// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package cookie_test

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/canonical/secure-token-service/internal/cookie"
	"github.com/chmike/securecookie"
)

func TestNewCookieManager_KeyValidation(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{name: "empty key (0 bytes)", keyLen: 0, wantErr: true},
		{name: "1 byte key", keyLen: 1, wantErr: true},
		{name: "short key (16 bytes)", keyLen: 16, wantErr: true},
		{name: "31 bytes key", keyLen: 31, wantErr: true},
		{name: "exact key (32 bytes)", keyLen: 32, wantErr: false},
		{name: "long key (64 bytes)", keyLen: 64, wantErr: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keyLen)
			if tc.keyLen > 0 {
				_, err := rand.Read(key)
				if err != nil {
					t.Fatalf("rand.Read failed: %v", err)
				}
			}

			cm, err := cookie.NewCookieManager(key)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, cookie.ErrKeyTooShort) {
					t.Fatalf("expected ErrKeyTooShort, got %v", err)
				}
				if cm != nil {
					t.Fatal("expected nil CookieManager on error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cm == nil {
				t.Fatal("NewCookieManager returned nil")
			}

			encoded, err := cm.Encode("test", "value")
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}
			decoded, err := cm.Decode("test", encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}
			if decoded != "value" {
				t.Errorf("got %q, want %q", decoded, "value")
			}
		})
	}
}

func TestCookieManager_EncodeDecode(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm, err := cookie.NewCookieManager(hashKey)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	tests := []struct {
		name       string
		cookieName string
		value      string
	}{
		{name: "session id", cookieName: "session_id", value: "test-session-value-123"},
		{name: "empty value", cookieName: "session_id", value: ""},
		{name: "long value", cookieName: "data", value: "a-very-long-value-that-exceeds-typical-lengths-1234567890abcdef"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := cm.Encode(tc.cookieName, tc.value)
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}
			if encoded == "" {
				t.Error("Encoded cookie is empty")
			}

			decoded, err := cm.Decode(tc.cookieName, encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}
			if decoded != tc.value {
				t.Errorf("got %q, want %q", decoded, tc.value)
			}
		})
	}
}

func TestCookieManager_DecodeInvalid(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm, err := cookie.NewCookieManager(hashKey)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	tests := []struct {
		name       string
		cookieName string
		value      string
	}{
		{name: "invalid value", cookieName: "session_id", value: "invalid-cookie-value"},
		{name: "empty value", cookieName: "session_id", value: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cm.Decode(tc.cookieName, tc.value)
			if err == nil {
				t.Error("Expected error when decoding invalid cookie, got nil")
			}
		})
	}
}

func TestCookieManager_WrongKey(t *testing.T) {
	hashKey1 := securecookie.MustGenerateRandomKey()
	cm1, err := cookie.NewCookieManager(hashKey1)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	hashKey2 := securecookie.MustGenerateRandomKey()
	cm2, err := cookie.NewCookieManager(hashKey2)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	encoded, err := cm1.Encode("session_id", "secret-data")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	_, err = cm2.Decode("session_id", encoded)
	if err == nil {
		t.Error("Expected error when decoding with different keys, got nil")
	}
}

func TestCookieManager_OIDCState(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm, err := cookie.NewCookieManager(hashKey)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	tests := []struct {
		name     string
		returnTo string
	}{
		{name: "dashboard return", returnTo: "/dashboard"},
		{name: "root return", returnTo: "/"},
		{name: "complex path", returnTo: "/settings/profile?tab=security"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)

			state, err := cm.SetOIDCState(w, r, tc.returnTo)
			if err != nil {
				t.Fatalf("SetOIDCState failed: %v", err)
			}
			if state == "" {
				t.Fatal("Returned state is empty")
			}

			// Extract oauth_state cookie from response
			var stateCookie *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == "oauth_state" {
					stateCookie = c
					break
				}
			}
			if stateCookie == nil {
				t.Fatal("oauth_state cookie not found in response")
			}

			// GetOIDCState with valid cookie
			rGet := httptest.NewRequest("GET", "/", nil)
			rGet.AddCookie(stateCookie)

			stateData, err := cm.GetOIDCState(rGet)
			if err != nil {
				t.Fatalf("GetOIDCState failed: %v", err)
			}
			if stateData["state"] != state {
				t.Errorf("state mismatch: got %q, want %q", stateData["state"], state)
			}
			if stateData["return_to"] != tc.returnTo {
				t.Errorf("return_to mismatch: got %q, want %q", stateData["return_to"], tc.returnTo)
			}

			// ClearOIDCState
			wClear := httptest.NewRecorder()
			cm.ClearOIDCState(wClear, r)
			clearCookies := wClear.Result().Cookies()
			if len(clearCookies) == 0 {
				t.Fatal("No cookies set in clear response")
			}
			if clearCookies[0].MaxAge >= 0 {
				t.Errorf("ClearOIDCState did not expire cookie: MaxAge=%d", clearCookies[0].MaxAge)
			}
		})
	}
}

func TestCookieManager_GetOIDCState_NoCookie(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm, err := cookie.NewCookieManager(hashKey)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	r := httptest.NewRequest("GET", "/callback", nil)

	_, err = cm.GetOIDCState(r)
	if err == nil {
		t.Error("Expected error when no state cookie present, got nil")
	}
}

func TestCookieManager_OIDCNonce(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm, err := cookie.NewCookieManager(hashKey)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	tests := []struct {
		name string
	}{
		{name: "basic nonce flow"},
		{name: "second nonce flow"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)

			nonce, err := cm.SetOIDCNonce(w, r)
			if err != nil {
				t.Fatalf("SetOIDCNonce failed: %v", err)
			}
			if nonce == "" {
				t.Fatal("Returned nonce is empty")
			}

			// Extract oauth_nonce cookie
			var nonceCookie *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == "oauth_nonce" {
					nonceCookie = c
					break
				}
			}
			if nonceCookie == nil {
				t.Fatal("oauth_nonce cookie not found")
			}

			// GetOIDCNonce with valid cookie
			rGet := httptest.NewRequest("GET", "/", nil)
			rGet.AddCookie(nonceCookie)

			gotNonce, err := cm.GetOIDCNonce(rGet)
			if err != nil {
				t.Fatalf("GetOIDCNonce failed: %v", err)
			}
			if gotNonce != nonce {
				t.Errorf("nonce mismatch: got %q, want %q", gotNonce, nonce)
			}

			// ClearOIDCNonce
			wClear := httptest.NewRecorder()
			cm.ClearOIDCNonce(wClear, r)
			clearCookies := wClear.Result().Cookies()
			if len(clearCookies) == 0 {
				t.Fatal("No cookies set in clear response")
			}
			if clearCookies[0].MaxAge >= 0 {
				t.Errorf("ClearOIDCNonce did not expire cookie")
			}
		})
	}
}

func TestCookieManager_GetOIDCNonce_NoCookie(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm, err := cookie.NewCookieManager(hashKey)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	r := httptest.NewRequest("GET", "/callback", nil)

	_, err = cm.GetOIDCNonce(r)
	if err == nil {
		t.Error("Expected error when no nonce cookie present, got nil")
	}
}

func TestCookieManager_SecureFlag(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm, err := cookie.NewCookieManager(hashKey)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	tests := []struct {
		name           string
		forwardedProto string
		expectSecure   bool
	}{
		{
			name:           "HTTP request (no forwarded proto)",
			forwardedProto: "",
			expectSecure:   false,
		},
		{
			name:           "HTTPS via X-Forwarded-Proto",
			forwardedProto: "https",
			expectSecure:   true,
		},
		{
			name:           "HTTP via X-Forwarded-Proto",
			forwardedProto: "http",
			expectSecure:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "http://example.com", nil)
			if tc.forwardedProto != "" {
				r.Header.Set("X-Forwarded-Proto", tc.forwardedProto)
			}

			_, err := cm.SetOIDCState(w, r, "/")
			if err != nil {
				t.Fatalf("SetOIDCState failed: %v", err)
			}

			cookies := w.Result().Cookies()
			if len(cookies) == 0 {
				t.Fatal("No cookies set")
			}

			if cookies[0].Secure != tc.expectSecure {
				t.Errorf("Secure flag: got %v, want %v", cookies[0].Secure, tc.expectSecure)
			}
		})
	}
}

func TestCookieManager_SetSessionCookie(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm, err := cookie.NewCookieManager(hashKey)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://example.com/test", nil)
	r.TLS = &tls.ConnectionState{} // Simulated TLS

	sessionID := "test-session-uuid-12345"
	expiresAt := time.Now().Add(24 * time.Hour).Truncate(time.Second)

	err = cm.SetSessionCookie(w, r, sessionID, expiresAt)
	if err != nil {
		t.Fatalf("SetSessionCookie failed: %v", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	c := cookies[0]
	if c.Name != "session_id" {
		t.Errorf("cookie name: got %q, want session_id", c.Name)
	}
	if !c.HttpOnly {
		t.Errorf("expected HttpOnly to be true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite to be Lax (%v), got %v", http.SameSiteLaxMode, c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("cookie path: got %q, want /", c.Path)
	}
	if !c.Secure {
		t.Errorf("expected Secure to be true on TLS request")
	}
	if !c.Expires.Equal(expiresAt) {
		t.Errorf("cookie expires: got %v, want %v", c.Expires, expiresAt)
	}

	// Verify the session ID decodes properly
	decoded, err := cm.Decode("session_id", c.Value)
	if err != nil {
		t.Fatalf("failed to decode session cookie: %v", err)
	}
	if decoded != sessionID {
		t.Errorf("decoded session ID: got %q, want %q", decoded, sessionID)
	}
}

func TestCookieManager_ClearSessionCookie(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm, err := cookie.NewCookieManager(hashKey)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://example.com/logout", nil)
	r.Header.Set("X-Forwarded-Proto", "https")

	cm.ClearSessionCookie(w, r)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	c := cookies[0]
	if c.Name != "session_id" {
		t.Errorf("cookie name: got %q, want session_id", c.Name)
	}
	if c.Value != "" {
		t.Errorf("expected empty value on cleared cookie, got %q", c.Value)
	}
	if !c.HttpOnly {
		t.Errorf("expected HttpOnly to be true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite to be Lax, got %v", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("cookie path: got %q, want /", c.Path)
	}
	if !c.Secure {
		t.Errorf("expected Secure to be true on X-Forwarded-Proto: https")
	}
	if c.MaxAge >= 0 {
		t.Errorf("expected MaxAge < 0, got %d", c.MaxAge)
	}
	if !c.Expires.Equal(time.Unix(0, 0)) {
		t.Errorf("expected Expires to be epoch, got %v", c.Expires)
	}
}

func TestCookieManager_DynamicSecureEvaluation(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm, err := cookie.NewCookieManager(hashKey)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	tests := []struct {
		name         string
		tls          bool
		headerProto  string
		expectSecure bool
	}{
		{
			name:         "plain HTTP without header",
			tls:          false,
			headerProto:  "",
			expectSecure: false,
		},
		{
			name:         "direct TLS",
			tls:          true,
			headerProto:  "",
			expectSecure: true,
		},
		{
			name:         "X-Forwarded-Proto https",
			tls:          false,
			headerProto:  "https",
			expectSecure: true,
		},
		{
			name:         "X-Forwarded-Proto HTTPS (case-insensitive)",
			tls:          false,
			headerProto:  "HTTPS",
			expectSecure: true,
		},
		{
			name:         "X-Forwarded-Proto http",
			tls:          false,
			headerProto:  "http",
			expectSecure: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "http://example.com", nil)
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if tc.headerProto != "" {
				r.Header.Set("X-Forwarded-Proto", tc.headerProto)
			}

			// Test SetSessionCookie
			err := cm.SetSessionCookie(w, r, "test-sess", time.Now().Add(time.Hour))
			if err != nil {
				t.Fatalf("SetSessionCookie failed: %v", err)
			}
			cookies := w.Result().Cookies()
			if len(cookies) == 0 {
				t.Fatal("no cookies set")
			}
			if cookies[0].Secure != tc.expectSecure {
				t.Errorf("SetSessionCookie Secure: got %v, want %v", cookies[0].Secure, tc.expectSecure)
			}

			// Test ClearSessionCookie
			wClear := httptest.NewRecorder()
			cm.ClearSessionCookie(wClear, r)
			clearCookies := wClear.Result().Cookies()
			if len(clearCookies) == 0 {
				t.Fatal("no cookies set on clear")
			}
			if clearCookies[0].Secure != tc.expectSecure {
				t.Errorf("ClearSessionCookie Secure: got %v, want %v", clearCookies[0].Secure, tc.expectSecure)
			}

			// Test SetAuthState
			wState := httptest.NewRecorder()
			_, err = cm.SetAuthState(wState, r, cookie.AuthState{ReturnTo: "/test", Provider: "openid"})
			if err != nil {
				t.Fatalf("SetAuthState failed: %v", err)
			}
			stateCookies := wState.Result().Cookies()
			if len(stateCookies) == 0 {
				t.Fatal("no state cookies set")
			}
			if stateCookies[0].Secure != tc.expectSecure {
				t.Errorf("SetAuthState Secure: got %v, want %v", stateCookies[0].Secure, tc.expectSecure)
			}
		})
	}
}

func TestCookieManager_AuthState(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm, err := cookie.NewCookieManager(hashKey)
	if err != nil {
		t.Fatalf("NewCookieManager failed: %v", err)
	}

	tests := []struct {
		name         string
		input        cookie.AuthState
		wantProvider string
	}{
		{
			name: "openid provider with return_to",
			input: cookie.AuthState{
				ReturnTo: "/dashboard",
				Provider: "openid",
			},
			wantProvider: "openid",
		},
		{
			name: "oidc provider explicit",
			input: cookie.AuthState{
				ReturnTo: "/settings",
				Provider: "oidc",
			},
			wantProvider: "oidc",
		},
		{
			name: "default provider when empty",
			input: cookie.AuthState{
				ReturnTo: "/",
				Provider: "",
			},
			wantProvider: "oidc",
		},
		{
			name: "explicit state provided",
			input: cookie.AuthState{
				State:    "custom-pre-generated-state",
				ReturnTo: "/custom",
				Provider: "openid",
			},
			wantProvider: "openid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)

			returnedState, err := cm.SetAuthState(w, r, tc.input)
			if err != nil {
				t.Fatalf("SetAuthState failed: %v", err)
			}
			if returnedState == "" {
				t.Fatal("returned state is empty")
			}
			if tc.input.State != "" && returnedState != tc.input.State {
				t.Errorf("state: got %q, want %q", returnedState, tc.input.State)
			}

			// Find oauth_state cookie
			var stateCookie *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == "oauth_state" {
					stateCookie = c
					break
				}
			}
			if stateCookie == nil {
				t.Fatal("oauth_state cookie not found in response")
			}

			// GetAuthState
			rGet := httptest.NewRequest("GET", "/", nil)
			rGet.AddCookie(stateCookie)

			gotState, err := cm.GetAuthState(rGet)
			if err != nil {
				t.Fatalf("GetAuthState failed: %v", err)
			}
			if gotState.State != returnedState {
				t.Errorf("state mismatch: got %q, want %q", gotState.State, returnedState)
			}
			if gotState.ReturnTo != tc.input.ReturnTo {
				t.Errorf("return_to mismatch: got %q, want %q", gotState.ReturnTo, tc.input.ReturnTo)
			}
			if gotState.Provider != tc.wantProvider {
				t.Errorf("provider mismatch: got %q, want %q", gotState.Provider, tc.wantProvider)
			}

			// ClearAuthState
			wClear := httptest.NewRecorder()
			cm.ClearAuthState(wClear, r)
			clearCookies := wClear.Result().Cookies()
			if len(clearCookies) == 0 {
				t.Fatal("no cookies set in clear response")
			}
			if clearCookies[0].MaxAge >= 0 {
				t.Errorf("ClearAuthState did not expire cookie: MaxAge=%d", clearCookies[0].MaxAge)
			}
		})
	}
}

