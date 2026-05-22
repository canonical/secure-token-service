// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package cookie_test

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/canonical/secure-token-service/internal/cookie"
	"github.com/chmike/securecookie"
)

func TestNewCookieManager_KeyDerivation(t *testing.T) {
	tests := []struct {
		name   string
		keyLen int
	}{
		{name: "short key (16 bytes)", keyLen: 16},
		{name: "exact key (32 bytes)", keyLen: 32},
		{name: "long key (64 bytes)", keyLen: 64},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keyLen)
			rand.Read(key)

			cm := cookie.NewCookieManager(key)
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
	cm := cookie.NewCookieManager(hashKey)

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
	cm := cookie.NewCookieManager(hashKey)

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
	cm1 := cookie.NewCookieManager(hashKey1)

	hashKey2 := securecookie.MustGenerateRandomKey()
	cm2 := cookie.NewCookieManager(hashKey2)

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
	cm := cookie.NewCookieManager(hashKey)

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
	cm := cookie.NewCookieManager(hashKey)

	r := httptest.NewRequest("GET", "/callback", nil)

	_, err := cm.GetOIDCState(r)
	if err == nil {
		t.Error("Expected error when no state cookie present, got nil")
	}
}

func TestCookieManager_OIDCNonce(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm := cookie.NewCookieManager(hashKey)

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
	cm := cookie.NewCookieManager(hashKey)

	r := httptest.NewRequest("GET", "/callback", nil)

	_, err := cm.GetOIDCNonce(r)
	if err == nil {
		t.Error("Expected error when no nonce cookie present, got nil")
	}
}

func TestCookieManager_SecureFlag(t *testing.T) {
	hashKey := securecookie.MustGenerateRandomKey()
	cm := cookie.NewCookieManager(hashKey)

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
