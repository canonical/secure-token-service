// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package openid

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultProviderURL is the default Ubuntu One OpenID 2.0 endpoint.
	DefaultProviderURL = "https://login.ubuntu.com/+openid"
	// OpenIDNS is the OpenID 2.0 namespace URI.
	OpenIDNS = "http://specs.openid.net/auth/2.0"
	// OpenIDIdentifierSelect indicates user identifier selection at OP.
	OpenIDIdentifierSelect = "http://specs.openid.net/auth/2.0/identifier_select"
	// AXNS is the Attribute Exchange 1.0 namespace URI.
	AXNS = "http://openid.net/srv/ax/1.0"
	// SREGNS is the Simple Registration Extension 1.1 namespace URI.
	SREGNS = "http://openid.net/extensions/sreg/1.1"
	// SREGNS10 is the Simple Registration Extension 1.0 namespace URI.
	SREGNS10 = "http://openid.net/sreg/1.0"
	// AXSchemaEmail is the AX schema URI for user email address.
	AXSchemaEmail = "http://axschema.org/contact/email"
	// AXSchemaNickname is the AX schema URI for user nickname / friendly name.
	AXSchemaNickname = "http://axschema.org/namePerson/friendly"
	// AXSchemaFullname is the AX schema URI for user full person name.
	AXSchemaFullname = "http://axschema.org/namePerson"
)

// NonceCache defines an interface for tracking and preventing replay of OpenID response_nonces.
type NonceCache interface {
	CheckAndRecord(nonce string, ttl time.Duration) bool
}

// MemoryNonceCache is a thread-safe in-memory implementation of NonceCache.
type MemoryNonceCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// NewMemoryNonceCache creates a new in-memory nonce cache.
func NewMemoryNonceCache() *MemoryNonceCache {
	return &MemoryNonceCache{
		entries: make(map[string]time.Time),
	}
}

// CheckAndRecord checks if the nonce is already recorded (not expired).
// If seen, it returns false (replay detected).
// If not seen or expired, it records the nonce with expiration now + ttl and returns true.
// It also prunes expired entries on write to prevent unbounded memory growth.
func (c *MemoryNonceCache) CheckAndRecord(nonce string, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Prune expired entries
	for k, exp := range c.entries {
		if now.After(exp) {
			delete(c.entries, k)
		}
	}

	if exp, exists := c.entries[nonce]; exists && now.Before(exp) {
		return false
	}

	c.entries[nonce] = now.Add(ttl)
	return true
}

// HTTPClient defines an interface for executing HTTP requests, allowing mockability in tests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Claims holds extracted identity claims from an OpenID 2.0 assertion.
type Claims struct {
	Email     string                 `json:"email,omitempty"`
	Nickname  string                 `json:"nickname,omitempty"`
	FullName  string                 `json:"name,omitempty"`
	ClaimedID string                 `json:"claimed_id,omitempty"`
	Raw       map[string]interface{} `json:"raw,omitempty"`
}

// UserID returns the resolved user identifier according to the required hierarchy:
// 1. Email (if available)
// 2. Nickname / preferred_username (if email unavailable)
// 3. ClaimedID (if nickname and email unavailable)
func (c *Claims) UserID() (string, error) {
	if c.Email != "" {
		return c.Email, nil
	}
	if c.Nickname != "" {
		return c.Nickname, nil
	}
	if c.ClaimedID != "" {
		return c.ClaimedID, nil
	}
	return "", errors.New("no valid user identity found in OpenID response")
}

// NormalizedClaims returns a map of normalized claims suitable for storing in a session
// and minting into internal JWTs.
func (c *Claims) NormalizedClaims() map[string]interface{} {
	m := make(map[string]interface{})
	if c.Email != "" {
		m["email"] = c.Email
	}
	if c.Nickname != "" {
		m["nickname"] = c.Nickname
		m["preferred_username"] = c.Nickname
	}
	if c.FullName != "" {
		m["name"] = c.FullName
	}
	if c.ClaimedID != "" {
		m["claimed_id"] = c.ClaimedID
	}
	m["idp_provider"] = "openid"
	return m
}

// Client represents an OpenID 2.0 relying party client for Ubuntu One.
type Client struct {
	providerURL string
	realm       string
	httpClient  HTTPClient
	nonceCache  NonceCache
}

// NewClient creates a new Ubuntu One OpenID client.
func NewClient(providerURL, realm string, httpClient HTTPClient) *Client {
	if providerURL == "" {
		providerURL = DefaultProviderURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		providerURL: providerURL,
		realm:       realm,
		httpClient:  httpClient,
		nonceCache:  NewMemoryNonceCache(),
	}
}

// WithNonceCache sets a custom NonceCache on the client.
func (c *Client) WithNonceCache(nc NonceCache) *Client {
	c.nonceCache = nc
	return c
}

// ProviderURL returns the configured OpenID provider endpoint.
func (c *Client) ProviderURL() string {
	return c.providerURL
}

// Realm returns the configured realm.
func (c *Client) Realm() string {
	return c.realm
}

// BuildAuthURL constructs the OpenID 2.0 redirect URL to initiate authentication with Ubuntu One.
// If stateToken is provided, it is appended to returnToURL so Ubuntu One reflects it back on callback.
func (c *Client) BuildAuthURL(returnToURL, stateToken string) (string, error) {
	if returnToURL == "" {
		return "", errors.New("return_to URL is required")
	}

	u, err := url.Parse(returnToURL)
	if err != nil {
		return "", fmt.Errorf("invalid return_to URL: %w", err)
	}

	// Add state parameter to returnToURL if provided
	if stateToken != "" {
		q := u.Query()
		q.Set("state", stateToken)
		u.RawQuery = q.Encode()
	}
	effectiveReturnTo := u.String()

	// Determine realm
	realm := c.realm
	if realm == "" {
		// Default realm to scheme + host of return_to
		realm = fmt.Sprintf("%s://%s/", u.Scheme, u.Host)
	}

	provURL, err := url.Parse(c.providerURL)
	if err != nil {
		return "", fmt.Errorf("invalid provider URL: %w", err)
	}

	q := provURL.Query()
	q.Set("openid.ns", OpenIDNS)
	q.Set("openid.mode", "checkid_setup")
	q.Set("openid.claimed_id", OpenIDIdentifierSelect)
	q.Set("openid.identity", OpenIDIdentifierSelect)
	q.Set("openid.return_to", effectiveReturnTo)
	q.Set("openid.realm", realm)

	// Simple Registration (SREG) 1.1 request (Canonical SSO / Launchpad standard)
	q.Set("openid.ns.sreg", SREGNS)
	q.Set("openid.sreg.required", "email,nickname")
	q.Set("openid.sreg.optional", "fullname")

	// Attribute Exchange (AX) 1.0 request
	q.Set("openid.ns.ax", AXNS)
	q.Set("openid.ax.mode", "fetch_request")
	q.Set("openid.ax.type.email", AXSchemaEmail)
	q.Set("openid.ax.type.nickname", AXSchemaNickname)
	q.Set("openid.ax.type.fullname", AXSchemaFullname)
	q.Set("openid.ax.required", "email,nickname,fullname")

	provURL.RawQuery = q.Encode()
	return provURL.String(), nil
}

// VerifyCallback verifies an OpenID 2.0 callback response via direct HTTP POST (check_authentication).
func (c *Client) VerifyCallback(ctx context.Context, r *http.Request, expectedReturnTo string) (*Claims, error) {
	q := r.URL.Query()

	mode := q.Get("openid.mode")
	if mode == "" {
		return nil, errors.New("missing openid.mode in callback")
	}
	if mode == "cancel" {
		return nil, errors.New("openid authentication was cancelled by user")
	}
	if mode != "id_res" {
		return nil, fmt.Errorf("unexpected openid.mode: %s", mode)
	}

	returnTo := q.Get("openid.return_to")
	if returnTo == "" {
		return nil, errors.New("openid: missing openid.return_to in callback")
	}
	if expectedReturnTo != "" && returnTo != expectedReturnTo {
		return nil, fmt.Errorf("openid: return_to mismatch: got %q, expected %q", returnTo, expectedReturnTo)
	}

	nonce := q.Get("openid.response_nonce")
	if nonce == "" {
		return nil, errors.New("missing openid.response_nonce in callback")
	}
	// Validate nonce timestamp if in ISO8601/RFC3339 format
	if len(nonce) >= 20 {
		if t, err := time.Parse(time.RFC3339, nonce[:20]); err == nil {
			skew := time.Since(t)
			if skew < -5*time.Minute || skew > 5*time.Minute {
				return nil, fmt.Errorf("openid response_nonce timestamp out of acceptable skew: %v", t)
			}
		}
	}

	if c.nonceCache != nil && !c.nonceCache.CheckAndRecord(nonce, 10*time.Minute) {
		return nil, fmt.Errorf("openid response_nonce replay detected: %s", nonce)
	}

	// Prepare direct verification request parameters:
	// Copy all openid.* parameters and change openid.mode to check_authentication
	form := make(url.Values)
	for k, v := range q {
		if strings.HasPrefix(k, "openid.") {
			form[k] = v
		}
	}
	form.Set("openid.mode", "check_authentication")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.providerURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create check_authentication request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("check_authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("check_authentication returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read check_authentication response: %w", err)
	}

	if !IsValidResponse(string(bodyBytes)) {
		return nil, errors.New("openid signature verification failed: is_valid is false")
	}

	return ExtractClaims(q), nil
}

// IsValidResponse checks if the OpenID provider's key-value response contains is_valid:true.
func IsValidResponse(body string) bool {
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if key == "is_valid" && val == "true" {
				return true
			}
		}
	}
	return false
}

// ExtractClaims extracts Attribute Exchange and identity attributes from query parameters.
func ExtractClaims(q url.Values) *Claims {
	claims := &Claims{
		Raw: make(map[string]interface{}),
	}

	for k, v := range q {
		if len(v) > 0 {
			claims.Raw[k] = v[0]
		}
	}

	// 1. Claimed ID / Identity
	if val := q.Get("openid.claimed_id"); val != "" {
		claims.ClaimedID = val
	} else if val := q.Get("openid.identity"); val != "" {
		claims.ClaimedID = val
	}

	// 2. Discover AX and SREG alias prefixes
	axPrefixes := []string{"ax", "ext1"}
	sregPrefixes := []string{"sreg"}

	for k, v := range q {
		if strings.HasPrefix(k, "openid.ns.") && len(v) > 0 {
			alias := strings.TrimPrefix(k, "openid.ns.")
			nsVal := v[0]
			if nsVal == AXNS || strings.HasPrefix(nsVal, "http://openid.net/srv/ax/") {
				axPrefixes = append(axPrefixes, alias)
			}
			if nsVal == SREGNS || nsVal == SREGNS10 || strings.Contains(strings.ToLower(nsVal), "sreg") {
				sregPrefixes = append(sregPrefixes, alias)
			}
		}
	}

	// Helper to find attribute value by alias or schema URI
	findAttr := func(attrName string, schemaURIs ...string) string {
		// 1. Check SREG prefixes: openid.<sregPrefix>.<attrName>
		for _, prefix := range sregPrefixes {
			if val := q.Get(fmt.Sprintf("openid.%s.%s", prefix, attrName)); val != "" {
				return val
			}
		}

		// 2. Check AX prefixes
		for _, prefix := range axPrefixes {
			// Direct alias: openid.<prefix>.value.<attrName>
			if val := q.Get(fmt.Sprintf("openid.%s.value.%s", prefix, attrName)); val != "" {
				return val
			}
			// Multi-value indexed alias: openid.<prefix>.value.<attrName>.1
			if val := q.Get(fmt.Sprintf("openid.%s.value.%s.1", prefix, attrName)); val != "" {
				return val
			}
			// Search by registered type URI: openid.<prefix>.type.<alias> == schemaURI
			for _, schemaURI := range schemaURIs {
				for k, v := range q {
					typePrefix := fmt.Sprintf("openid.%s.type.", prefix)
					if strings.HasPrefix(k, typePrefix) && len(v) > 0 && v[0] == schemaURI {
						typeAlias := strings.TrimPrefix(k, typePrefix)
						if val := q.Get(fmt.Sprintf("openid.%s.value.%s", prefix, typeAlias)); val != "" {
							return val
						}
						if val := q.Get(fmt.Sprintf("openid.%s.value.%s.1", prefix, typeAlias)); val != "" {
							return val
						}
					}
				}
			}
		}

		// 3. Fallback direct openid.<attrName>
		if val := q.Get(fmt.Sprintf("openid.%s", attrName)); val != "" {
			return val
		}

		// 4. Fallback direct query parameter
		if val := q.Get(attrName); val != "" {
			return val
		}

		return ""
	}

	claims.Email = findAttr("email",
		AXSchemaEmail,
		"http://schema.openid.net/contact/email",
		"http://openid.net/schema/contact/email",
	)
	claims.Nickname = findAttr("nickname",
		AXSchemaNickname,
		"http://schema.openid.net/namePerson/friendly",
		"http://openid.net/schema/namePerson/friendly",
	)
	claims.FullName = findAttr("fullname",
		AXSchemaFullname,
		"http://schema.openid.net/namePerson",
		"http://openid.net/schema/namePerson",
	)
	if claims.FullName == "" {
		claims.FullName = findAttr("name",
			AXSchemaFullname,
			"http://schema.openid.net/namePerson",
			"http://openid.net/schema/namePerson",
		)
	}
	if claims.FullName == "" {
		first := findAttr("first_name", "http://axschema.org/namePerson/first")
		last := findAttr("last_name", "http://axschema.org/namePerson/last")
		if first != "" || last != "" {
			claims.FullName = strings.TrimSpace(first + " " + last)
		}
	}

	return claims
}
