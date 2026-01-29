// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

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

func (p *StandardOIDCProvider) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.oauth2Config.Exchange(ctx, code, opts...)
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

func (t *StandardIDToken) GetNonce() string {
	return t.token.Nonce
}

func (t *StandardIDToken) GetSubject() string {
	return t.token.Subject
}

func (t *StandardIDToken) GetExpiry() time.Time {
	return t.token.Expiry
}

func (t *StandardIDToken) GetOriginalToken() string {
	return t.raw
}
