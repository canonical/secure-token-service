// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"context"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// StandardOIDCProvider adapts the concrete oidc/oauth2 implementations to the OIDCProvider interface.
type StandardOIDCProvider struct {
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
}

// NewOIDCProvider creates a new StandardOIDCProvider.
func NewOIDCProvider(provider *oidc.Provider, cfg *oauth2.Config) *StandardOIDCProvider {
	return &StandardOIDCProvider{
		provider:     provider,
		oauth2Config: cfg,
	}
}

func (p *StandardOIDCProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return p.oauth2Config.AuthCodeURL(state, opts...)
}

func (p *StandardOIDCProvider) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (OAuth2Token, error) {
	token, err := p.oauth2Config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, err
	}
	return &StandardOAuth2Token{token: token}, nil
}

func (p *StandardOIDCProvider) Verifier() interface{} {
	return p.provider.Verifier(&oidc.Config{ClientID: p.oauth2Config.ClientID})
}

func (p *StandardOIDCProvider) VerifyIDToken(ctx context.Context, rawIDToken string) (IDToken, error) {
	verifier := p.provider.Verifier(&oidc.Config{ClientID: p.oauth2Config.ClientID})
	token, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	return &StandardIDToken{token: token, raw: rawIDToken}, nil
}

// StandardIDToken wraps oidc.IDToken to implement IDToken interface.
type StandardIDToken struct {
	token *oidc.IDToken
	raw   string
}

func (t *StandardIDToken) Claims(v interface{}) error {
	return t.token.Claims(v)
}

func (t *StandardIDToken) Subject() string {
	return t.token.Subject
}

func (t *StandardIDToken) GetNonce() (string, error) {
	return t.token.Nonce, nil
}

func (t *StandardIDToken) GetSubject() (string, error) {
	return t.token.Subject, nil
}

func (t *StandardIDToken) GetExpiry() time.Time {
	return t.token.Expiry
}

func (t *StandardIDToken) GetOriginalToken() string {
	return t.raw
}

// StandardOAuth2Token wraps oauth2.Token to implement OAuth2Token interface.
type StandardOAuth2Token struct {
	token *oauth2.Token
}

func (t *StandardOAuth2Token) Extra(key string) interface{} {
	return t.token.Extra(key)
}

func (t *StandardOAuth2Token) AccessToken() string {
	return t.token.AccessToken
}

func (t *StandardOAuth2Token) RefreshToken() string {
	return t.token.RefreshToken
}

func (t *StandardOAuth2Token) Expiry() time.Time {
	return t.token.Expiry
}
