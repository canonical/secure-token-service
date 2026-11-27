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
	GivenName string                 `json:"given_name,omitempty"`
	ClaimedID string                 `json:"claimed_id,omitempty"`
	Raw       map[string]interface{} `json:"raw,omitempty"`
}

// IsValidU1SSOID reports whether id is a valid short Ubuntu One SSO identifier
// suitable for use as a normalized u1_sso_id claim and OpenFGA object identifier
// (non-empty, <= 128 printable non-whitespace ASCII characters, containing no '/' or ':').
func IsValidU1SSOID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if c <= 0x20 || c >= 0x7f || c == '/' || c == ':' {
			return false
		}
	}
	return true
}

// ExtractU1SSOID extracts and validates the short Ubuntu One SSO identifier from
// a signed openid.claimed_id URL of the form "https://<host>/+id/<short_id>".
func ExtractU1SSOID(claimedID string) (string, error) {
	trimmed := strings.TrimSpace(claimedID)
	if trimmed == "" || trimmed == OpenIDIdentifierSelect {
		return "", errors.New("missing claimed_id in OpenID response")
	}
	u, err := url.Parse(trimmed)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("invalid claimed_id URL in OpenID response")
	}
	const idPrefix = "/+id/"
	if !strings.HasPrefix(u.Path, idPrefix) {
		return "", errors.New("claimed_id missing /+id/ prefix in OpenID response")
	}
	shortID := strings.TrimPrefix(u.Path, idPrefix)
	if !IsValidU1SSOID(shortID) {
		return "", errors.New("invalid u1_sso_id in OpenID claimed_id")
	}
	return shortID, nil
}

// U1SSOID returns the short Ubuntu One SSO identifier extracted from ClaimedID.
func (c *Claims) U1SSOID() (string, error) {
	return ExtractU1SSOID(c.ClaimedID)
}

// UserID resolves the session user identifier strictly from the short U1SSO ID
// extracted from signed ClaimedID ("https://<host>/+id/<short_id>") and requires
// a signed Email, failing closed without fallback when either is absent or invalid.
func (c *Claims) UserID() (string, error) {
	u1ID, err := c.U1SSOID()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(c.Email) == "" {
		return "", errors.New("missing email in OpenID response")
	}
	return u1ID, nil
}

// NormalizedClaims returns a map of normalized claims suitable for storing in a session
// and minting into internal JWTs.
func (c *Claims) NormalizedClaims() map[string]interface{} {
	m := make(map[string]interface{})
	if email := strings.TrimSpace(c.Email); email != "" {
		m["email"] = email
	}
	if c.Nickname != "" {
		m["nickname"] = c.Nickname
		m["preferred_username"] = c.Nickname
	}
	if c.FullName != "" {
		m["name"] = c.FullName
	}
	if c.GivenName != "" {
		m["given_name"] = c.GivenName
	}
	if u1ID, err := c.U1SSOID(); err == nil {
		m["u1_sso_id"] = u1ID
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
	// Reject duplicate or empty openid.* parameters (HTTP Parameter Pollution).
	// q.Get reads v[0], whereas check_authentication forwards all values and some OPs
	// (e.g. Ubuntu SSO / Django QueryDict) evaluate v[-1].
	for k, v := range q {
		if strings.HasPrefix(k, "openid.") && len(v) != 1 {
			return nil, fmt.Errorf("openid: duplicate or empty parameter %q", k)
		}
	}

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

	// Validate openid.signed covers required core assertion fields (OpenID 2.0 §10.1).
	// Note: "signed" itself is not required inside openid.signed per §10.1.
	signedFields, ok := parseSignedFields(q)
	if !ok {
		return nil, errors.New("openid: missing openid.signed in callback")
	}
	for _, reqField := range []string{"return_to", "response_nonce"} {
		if !signedFields[reqField] {
			return nil, fmt.Errorf("openid: required field %q is not covered by openid.signed", reqField)
		}
	}
	for _, condField := range []string{"op_endpoint", "assoc_handle", "claimed_id", "identity"} {
		if q.Get("openid."+condField) != "" && !signedFields[condField] {
			return nil, fmt.Errorf("openid: field %q is not covered by openid.signed", condField)
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

// ExtractClaims extracts Attribute Exchange and identity attributes strictly from
// fields covered by `openid.signed` in a verified OpenID 2.0 assertion.
// Unsigned parameters (including non-`openid.*` query parameters) are ignored.
func ExtractClaims(q url.Values) *Claims {
	claims := &Claims{
		Raw: make(map[string]interface{}),
	}

	for k, v := range q {
		if len(v) > 0 {
			claims.Raw[k] = v[0]
		}
	}

	// Build the set of fields covered by `openid.signed` (OpenID 2.0 §10.1).
	// Fail closed when `openid.signed` is missing or duplicated.
	signedFields, ok := parseSignedFields(q)
	if !ok {
		return claims
	}

	// signedGet returns the value for an `openid.*` parameter only when it has a
	// single value (preventing HPP) and its field name (without the `openid.` prefix)
	// is present in `openid.signed`.
	signedGet := func(key string) string {
		if !strings.HasPrefix(key, "openid.") {
			return ""
		}
		if !signedFields[strings.TrimPrefix(key, "openid.")] {
			return ""
		}
		vals := q[key]
		if len(vals) != 1 {
			return ""
		}
		return vals[0]
	}

	// 1. Claimed ID (must be signed; no fallback to openid.identity or identifier_select)
	if val := strings.TrimSpace(signedGet("openid.claimed_id")); val != "" && val != OpenIDIdentifierSelect {
		claims.ClaimedID = val
	}

	// 2. Discover AX and SREG alias prefixes from signed namespace declarations
	axPrefixes := []string{"ax", "ext1"}
	sregPrefixes := []string{"sreg"}

	for k := range q {
		if strings.HasPrefix(k, "openid.ns.") {
			nsVal := signedGet(k)
			if nsVal == "" {
				continue
			}
			alias := strings.TrimPrefix(k, "openid.ns.")
			if nsVal == AXNS || strings.HasPrefix(nsVal, "http://openid.net/srv/ax/") {
				axPrefixes = append(axPrefixes, alias)
			}
			if nsVal == SREGNS || nsVal == SREGNS10 || strings.Contains(strings.ToLower(nsVal), "sreg") {
				sregPrefixes = append(sregPrefixes, alias)
			}
		}
	}

	// Helper to find a signed attribute value by alias or schema URI
	findAttr := func(attrName string, schemaURIs ...string) string {
		// 1. Check SREG prefixes: openid.<sregPrefix>.<attrName>
		for _, prefix := range sregPrefixes {
			if val := signedGet(fmt.Sprintf("openid.%s.%s", prefix, attrName)); val != "" {
				return val
			}
		}

		// 2. Check AX prefixes
		for _, prefix := range axPrefixes {
			// Search by registered type URI: openid.<prefix>.type.<alias> == schemaURI
			for _, schemaURI := range schemaURIs {
				typePrefix := fmt.Sprintf("openid.%s.type.", prefix)
				for k := range q {
					if strings.HasPrefix(k, typePrefix) && signedGet(k) == schemaURI {
						typeAlias := strings.TrimPrefix(k, typePrefix)
						if val := signedGet(fmt.Sprintf("openid.%s.value.%s", prefix, typeAlias)); val != "" {
							return val
						}
						if val := signedGet(fmt.Sprintf("openid.%s.value.%s.1", prefix, typeAlias)); val != "" {
							return val
						}
					}
				}
			}
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
	claims.GivenName = findAttr("first_name",
		"http://axschema.org/namePerson/first",
		"http://schema.openid.net/namePerson/first",
	)
	if claims.FullName == "" {
		last := findAttr("last_name",
			"http://axschema.org/namePerson/last",
			"http://schema.openid.net/namePerson/last",
		)
		if claims.GivenName != "" || last != "" {
			claims.FullName = strings.TrimSpace(claims.GivenName + " " + last)
		}
	}

	return claims
}

// parseSignedFields parses a single-valued `openid.signed` parameter into a lookup set.
func parseSignedFields(q url.Values) (map[string]bool, bool) {
	vals, ok := q["openid.signed"]
	if !ok || len(vals) != 1 {
		return nil, false
	}
	signed := strings.TrimSpace(vals[0])
	if signed == "" {
		return nil, false
	}
	signedFields := make(map[string]bool)
	for _, field := range strings.Split(signed, ",") {
		if f := strings.TrimSpace(field); f != "" {
			signedFields[f] = true
		}
	}
	return signedFields, len(signedFields) > 0
}
