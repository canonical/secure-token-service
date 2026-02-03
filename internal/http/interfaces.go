// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package httpserver

import (
	"context"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/oauth2"
)

// KeyManager defines the interface for key operations.
type KeyManager interface {
	MintToken(subject, issuer, audience string, expirySeconds int, claims map[string]interface{}) (string, error)
	GetJWK() (jwk.Key, error)
	GetAllJWKS() (jwk.Set, error)
}

// AuthCookieManager defines the interface for cookie operations.
type AuthCookieManager interface {
	Encode(name, value string) (string, error)
	Decode(name, value string) (string, error)

	SetOIDCState(w http.ResponseWriter, r *http.Request, returnTo string) (string, error)
	GetOIDCState(r *http.Request) (map[string]string, error)
	ClearOIDCState(w http.ResponseWriter, r *http.Request)

	SetOIDCNonce(w http.ResponseWriter, r *http.Request) (string, error)
	GetOIDCNonce(r *http.Request) (string, error)
	ClearOIDCNonce(w http.ResponseWriter, r *http.Request)
}

// IDToken defines the interface for ID Token properties.
type IDToken interface {
	GetNonce() string
	GetSubject() string
	GetExpiry() time.Time
	GetOriginalToken() string // For IDTokenRaw
}

// OIDCProvider defines the interface for OIDC operations.
type OIDCProvider interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	VerifyIDToken(ctx context.Context, rawIDToken string) (IDToken, error)
}
