// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"context"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/oauth2"
)

// CookieManager defines the interface for secure cookie operations
type CookieManager interface {
	SetOIDCState(w http.ResponseWriter, r *http.Request, returnTo string) (string, error)
	GetOIDCState(r *http.Request) (map[string]string, error)
	ClearOIDCState(w http.ResponseWriter, r *http.Request)
	SetOIDCNonce(w http.ResponseWriter, r *http.Request) (string, error)
	GetOIDCNonce(r *http.Request) (string, error)
	ClearOIDCNonce(w http.ResponseWriter, r *http.Request)
}

// KeyManager defines the interface for JWT key management
type KeyManager interface {
	MintToken(subject, issuer, audience string, expirySeconds int, claims map[string]interface{}) (string, error)
	GetAllJWKS() (jwk.Set, error)
}

// AuthCookieManager defines the interface for authentication cookie operations
type AuthCookieManager interface {
	SetOIDCState(w http.ResponseWriter, r *http.Request, returnTo string) (string, error)
	GetOIDCState(r *http.Request) (map[string]string, error)
	ClearOIDCState(w http.ResponseWriter, r *http.Request)
	SetOIDCNonce(w http.ResponseWriter, r *http.Request) (string, error)
	GetOIDCNonce(r *http.Request) (string, error)
	ClearOIDCNonce(w http.ResponseWriter, r *http.Request)
	// Additional methods for session cookies
	Encode(name, value string) (string, error)
	Decode(name, value string) (string, error)
}

// IDToken defines the interface for ID token operations
type IDToken interface {
	Claims(v interface{}) error
	Subject() string
	// Additional methods for OIDC flow
	GetNonce() (string, error)
	GetSubject() (string, error)
	GetOriginalToken() string
}

// OAuth2Token defines the interface for OAuth2 token operations
type OAuth2Token interface {
	Extra(key string) interface{}
	AccessToken() string
	RefreshToken() string
	Expiry() time.Time
}

// OIDCProvider defines the interface for OIDC provider operations
type OIDCProvider interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (OAuth2Token, error)
	Verifier() interface{}
	VerifyIDToken(ctx context.Context, rawIDToken string) (IDToken, error)
}
