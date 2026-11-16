// Copyright 2026 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	chmike "github.com/chmike/securecookie/v2"
	"github.com/gorilla/securecookie"
)

var (
	hashKey    = []byte("very-secret-hash-key-32-bytes-!!")
	blockKey   = []byte("a-secret-block-key-16-bytes-!!!!")
	payload    = map[string]string{"user_id": "12345", "role": "admin"}
	cookieName = "session"
)

func BenchmarkGorillaEncodeDecode(b *testing.B) {
	s := securecookie.New(hashKey, blockKey)
	encoded, _ := s.Encode(cookieName, payload)

	for b.Loop() {
		var decoded map[string]string
		_ = s.Decode(cookieName, encoded, &decoded)
	}
}

func BenchmarkChmikеEncodeDecode(b *testing.B) {
	// chmike/securecookie uses an HTTP-based API, so we benchmark with mock HTTP objects
	keys, _ := chmike.NewKeyStore(hashKey)
	s, _ := chmike.New(cookieName, keys, time.Hour)

	// Marshal payload to bytes (chmike works with []byte)
	payloadBytes, _ := json.Marshal(payload)

	// Encode: Create a mock response writer and set the cookie
	w := httptest.NewRecorder()
	_ = s.SetValue(w, payloadBytes)

	// Extract the cookie value from the Set-Cookie header
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		b.Fatal("no cookie set")
	}
	cookieValue := cookies[0].Value

	// Create a request with the cookie for decoding (v2 prefixes the name with __Host-)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: s.Name(), Value: cookieValue})

	for b.Loop() {
		// Decode: Extract value from cookie
		decodedBytes, _, _ := s.Value(nil, req)
		var decoded map[string]string
		_ = json.Unmarshal(decodedBytes, &decoded)
	}
}
