package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	chmike "github.com/chmike/securecookie"
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var decoded map[string]string
		_ = s.Decode(cookieName, encoded, &decoded)
	}
}

func BenchmarkChmikеEncodeDecode(b *testing.B) {
	// chmike/securecookie uses an HTTP-based API, so we benchmark with mock HTTP objects
	s, _ := chmike.New(cookieName, hashKey, chmike.Params{Secure: true})

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

	// Create a request with the cookie for decoding
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Decode: Extract value from cookie
		decodedBytes, _ := s.GetValue(nil, req)
		var decoded map[string]string
		_ = json.Unmarshal(decodedBytes, &decoded)
	}
}
