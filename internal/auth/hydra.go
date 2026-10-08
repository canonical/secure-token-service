// Copyright 2026 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var (
	// ErrEmptyToken is returned when the token string is empty or whitespace.
	ErrEmptyToken = errors.New("token is required")
	// ErrTokenExpired is returned when the token expiration time is in the past.
	ErrTokenExpired = errors.New("token is expired")
	// ErrTokenExpiringSoon is returned when the token has less than 60 seconds of remaining lifetime.
	ErrTokenExpiringSoon = errors.New("token expiring in less than 60 seconds")
	// ErrInvalidSignature is returned when the token signature does not match or is malformed.
	ErrInvalidSignature = errors.New("invalid token signature")
	// ErrMissingSubject is returned when the token lacks both sub and client_id claims.
	ErrMissingSubject = errors.New("token missing subject")
	// ErrInvalidSubject is returned when the extracted subject or client_id exceeds 256 characters or contains control characters/newlines.
	ErrInvalidSubject = errors.New("token subject is invalid")
	// ErrJWKSUnavailable is returned when upstream JWKS cannot be retrieved.
	ErrJWKSUnavailable = errors.New("upstream JWKS unavailable")
	// ErrKeyNotFound is returned when the signing key ID (kid) is not present in the upstream JWKS.
	ErrKeyNotFound = errors.New("signing key not found in upstream JWKS")
	// ErrIssuerMismatch is returned when the token issuer does not match the configured expected issuer.
	ErrIssuerMismatch = errors.New("token issuer mismatch")
)

// VerifiedToken contains the extracted, validated claims from an upstream IdP access token.
type VerifiedToken struct {
	Subject   string
	ClientID  string
	ExpiresAt time.Time
	Claims    map[string]interface{}
}

// TokenVerifier defines the interface for verifying upstream IdP access tokens.
type TokenVerifier interface {
	Verify(ctx context.Context, tokenString string) (*VerifiedToken, error)
}

// HydraTokenVerifier verifies upstream OAuth2 Client Credentials tokens using Ory Hydra's JWKS.
type HydraTokenVerifier struct {
	jwksURL            string
	cache              *jwk.Cache
	staticKeySet       jwk.Set
	expectedIssuer     string
	cancel             context.CancelFunc
	clockSkewTolerance time.Duration
}

// Close stops the background JWKS caching routine and releases associated resources.
func (v *HydraTokenVerifier) Close() error {
	if v.cancel != nil {
		v.cancel()
	}
	return nil
}

// verifierConfig holds internal options for HydraTokenVerifier.
type verifierConfig struct {
	refreshInterval    time.Duration
	minRefreshInterval time.Duration
	httpClient         *http.Client
	expectedIssuer     string
	staticKeySet       jwk.Set
	clockSkewTolerance time.Duration
}

// VerifierOption configures a HydraTokenVerifier.
type VerifierOption func(*verifierConfig)

// WithRefreshInterval sets the interval for background JWKS refresh.
func WithRefreshInterval(d time.Duration) VerifierOption {
	return func(c *verifierConfig) {
		c.refreshInterval = d
	}
}

// WithMinRefreshInterval sets the minimum refresh interval for JWKS.
func WithMinRefreshInterval(d time.Duration) VerifierOption {
	return func(c *verifierConfig) {
		c.minRefreshInterval = d
	}
}

// WithHTTPClient sets a custom HTTP client for JWKS fetching.
func WithHTTPClient(client *http.Client) VerifierOption {
	return func(c *verifierConfig) {
		c.httpClient = client
	}
}

// WithExpectedIssuer sets the expected issuer claim to enforce.
func WithExpectedIssuer(issuer string) VerifierOption {
	return func(c *verifierConfig) {
		c.expectedIssuer = issuer
	}
}

// WithStaticKeySet configures a static jwk.Set (primarily for testing).
func WithStaticKeySet(set jwk.Set) VerifierOption {
	return func(c *verifierConfig) {
		c.staticKeySet = set
	}
}

// WithClockSkewTolerance sets the clock skew leeway duration for validating timestamps.
func WithClockSkewTolerance(d time.Duration) VerifierOption {
	return func(c *verifierConfig) {
		c.clockSkewTolerance = d
	}
}

// NewHydraTokenVerifier creates and initializes a new HydraTokenVerifier with preemptive JWKS caching.
func NewHydraTokenVerifier(ctx context.Context, jwksURL string, opts ...VerifierOption) (*HydraTokenVerifier, error) {
	cfg := &verifierConfig{
		refreshInterval:    10 * time.Minute,
		minRefreshInterval: 1 * time.Minute,
		clockSkewTolerance: 5 * time.Second,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	cacheCtx, cancel := context.WithCancel(ctx)

	verifier := &HydraTokenVerifier{
		jwksURL:            jwksURL,
		expectedIssuer:     cfg.expectedIssuer,
		staticKeySet:       cfg.staticKeySet,
		cancel:             cancel,
		clockSkewTolerance: cfg.clockSkewTolerance,
	}

	// If a static key set is provided, we skip remote cache initialization.
	if cfg.staticKeySet != nil {
		return verifier, nil
	}

	if jwksURL == "" {
		cancel()
		return nil, fmt.Errorf("jwksURL is required when no static key set is provided")
	}

	refreshWindow := cfg.refreshInterval / 2
	if refreshWindow < 1*time.Second {
		refreshWindow = 1 * time.Second
	}
	c := jwk.NewCache(cacheCtx, jwk.WithRefreshWindow(refreshWindow))
	regOpts := []jwk.RegisterOption{
		jwk.WithRefreshInterval(cfg.refreshInterval),
		jwk.WithMinRefreshInterval(cfg.minRefreshInterval),
	}
	if cfg.httpClient != nil {
		regOpts = append(regOpts, jwk.WithHTTPClient(cfg.httpClient))
	}

	if err := c.Register(jwksURL, regOpts...); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to register JWKS URL with cache: %w", err)
	}

	// Preemptively fetch the JWKS on startup to avoid request-time latency
	_, _ = c.Refresh(cacheCtx, jwksURL)

	verifier.cache = c
	return verifier, nil
}

// getKeySet retrieves the active jwk.Set, either from the static set or the preemptive cache.
func (v *HydraTokenVerifier) getKeySet(ctx context.Context) (jwk.Set, error) {
	if v.staticKeySet != nil {
		return v.staticKeySet, nil
	}
	if v.cache == nil {
		return nil, ErrJWKSUnavailable
	}
	set, err := v.cache.Get(ctx, v.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSUnavailable, err)
	}
	return set, nil
}

const maxSubjectLength = 256

func isValidSubject(s string) bool {
	if len(s) == 0 || len(s) > maxSubjectLength {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Verify validates the incoming upstream JWT: signature against Hydra JWKS, expiration, and subject.
func (v *HydraTokenVerifier) Verify(ctx context.Context, tokenString string) (*VerifiedToken, error) {
	if strings.TrimSpace(tokenString) == "" {
		return nil, ErrEmptyToken
	}

	set, err := v.getKeySet(ctx)
	if err != nil {
		return nil, err
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithLeeway(v.clockSkewTolerance))
	token, err := parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		kidVal, ok := t.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}
		kid, ok := kidVal.(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("invalid kid in token header")
		}

		key, found := set.LookupKeyID(kid)
		if !found && v.cache != nil {
			if refreshedSet, refreshErr := v.cache.Refresh(ctx, v.jwksURL); refreshErr == nil && refreshedSet != nil {
				set = refreshedSet
				key, found = set.LookupKeyID(kid)
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: kid %s", ErrKeyNotFound, kid)
		}

		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("failed to extract raw key: %w", err)
		}
		return rawKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, ErrKeyNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	if !token.Valid {
		return nil, ErrInvalidSignature
	}

	// Check issuer if expectedIssuer is set
	if v.expectedIssuer != "" {
		iss, _ := claims.GetIssuer()
		if iss != v.expectedIssuer {
			return nil, fmt.Errorf("%w: got %q, want %q", ErrIssuerMismatch, iss, v.expectedIssuer)
		}
	}

	// Verify expiration and threshold (must have at least 60s remaining)
	expVal, err := claims.GetExpirationTime()
	if err != nil || expVal == nil {
		return nil, fmt.Errorf("token missing expiration time")
	}
	expTime := expVal.Time
	now := time.Now()
	if expTime.Before(now) {
		return nil, ErrTokenExpired
	}
	if expTime.Sub(now) < 60*time.Second {
		return nil, ErrTokenExpiringSoon
	}

	// Extract and validate subject and client_id
	var clientID string
	if rawCID, ok := claims["client_id"]; ok && rawCID != nil {
		cidStr, isStr := rawCID.(string)
		if !isStr {
			return nil, ErrInvalidSubject
		}
		clientID = cidStr
	}

	sub, _ := claims.GetSubject()
	if rawSub, ok := claims["sub"]; ok && rawSub != nil {
		if _, isStr := rawSub.(string); !isStr {
			return nil, ErrInvalidSubject
		}
	}

	if sub == "" && clientID != "" {
		sub = clientID
	} else if clientID == "" && sub != "" {
		clientID = sub
	}

	if sub == "" {
		return nil, ErrMissingSubject
	}

	if !isValidSubject(sub) || !isValidSubject(clientID) {
		return nil, ErrInvalidSubject
	}

	return &VerifiedToken{
		Subject:   sub,
		ClientID:  clientID,
		ExpiresAt: expTime,
		Claims:    claims,
	}, nil
}
