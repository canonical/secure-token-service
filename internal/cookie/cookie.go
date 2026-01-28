package cookie

import (
	"fmt"

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
