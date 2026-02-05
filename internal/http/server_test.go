// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/canonical/secure-token-service/internal/session"
	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/oauth2"
)

// Mocks

type MockKeyManager struct {
	jwk jwk.Key
	err error
}

func (m *MockKeyManager) MintToken(subject, issuer, audience string, expirySeconds int, claims map[string]interface{}) (string, error) {
	return "mock_token", nil
}

func (m *MockKeyManager) GetJWK() (jwk.Key, error) {
	return m.jwk, m.err
}

func (m *MockKeyManager) GetAllJWKS() (jwk.Set, error) {
	set := jwk.NewSet()
	if m.jwk != nil {
		set.AddKey(m.jwk)
	}
	return set, m.err
}

type MockCookieManager struct {
	cookies map[string]string
	err     error
}

func NewMockCookieManager() *MockCookieManager {
	return &MockCookieManager{
		cookies: make(map[string]string),
	}
}

func (m *MockCookieManager) Encode(name, value string) (string, error) {
	return value, nil
}
func (m *MockCookieManager) Decode(name, value string) (string, error) {
	return value, nil
}

func (m *MockCookieManager) SetOIDCState(w http.ResponseWriter, r *http.Request, returnTo string) (string, error) {
	state := "mock_state"
	stateData := map[string]string{"state": state, "return_to": returnTo}
	bytes, _ := json.Marshal(stateData)
	m.cookies["oauth_state"] = string(bytes)
	return state, nil
}
func (m *MockCookieManager) GetOIDCState(r *http.Request) (map[string]string, error) {
	val, ok := m.cookies["oauth_state"]
	if !ok {
		return nil, fmt.Errorf("missing state cookie")
	}
	var data map[string]string
	json.Unmarshal([]byte(val), &data)
	return data, nil
}
func (m *MockCookieManager) ClearOIDCState(w http.ResponseWriter, r *http.Request) {
	delete(m.cookies, "oauth_state")
}

func (m *MockCookieManager) SetOIDCNonce(w http.ResponseWriter, r *http.Request) (string, error) {
	nonce := "mock_nonce"
	m.cookies["oauth_nonce"] = nonce
	return nonce, nil
}
func (m *MockCookieManager) GetOIDCNonce(r *http.Request) (string, error) {
	val, ok := m.cookies["oauth_nonce"]
	if !ok {
		return "", fmt.Errorf("missing nonce cookie")
	}
	return val, nil
}
func (m *MockCookieManager) ClearOIDCNonce(w http.ResponseWriter, r *http.Request) {
	delete(m.cookies, "oauth_nonce")
}

type MockIDToken struct {
	Nonce   string
	Subject string
	Expiry  time.Time
	Raw     string
}

func (m *MockIDToken) GetNonce() string         { return m.Nonce }
func (m *MockIDToken) GetSubject() string       { return m.Subject }
func (m *MockIDToken) GetExpiry() time.Time     { return m.Expiry }
func (m *MockIDToken) GetOriginalToken() string { return m.Raw }

type MockOIDCProvider struct {
	ExchangeToken *oauth2.Token
	ExchangeErr   error
	IDToken       IDToken
	IDTokenErr    error
}

func (m *MockOIDCProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return "http://idp/auth?state=" + state
}
func (m *MockOIDCProvider) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return m.ExchangeToken, m.ExchangeErr
}
func (m *MockOIDCProvider) VerifyIDToken(ctx context.Context, rawIDToken string) (IDToken, error) {
	return m.IDToken, m.IDTokenErr
}

type MockSessionStore struct {
	lastSession *session.Session
}

func (m *MockSessionStore) Set(ctx context.Context, s *session.Session) error {
	m.lastSession = s
	return nil
}
func (m *MockSessionStore) Get(ctx context.Context, id string) (*session.Session, error) {
	if m.lastSession != nil && m.lastSession.SessionID == id {
		return m.lastSession, nil
	}
	return nil, nil
}
func (m *MockSessionStore) Delete(ctx context.Context, id string) error                 { return nil }
func (m *MockSessionStore) RevokeUserSessions(ctx context.Context, userID string) error { return nil }

// Tests

func TestHandleJWKS(t *testing.T) {
	// Create a dummy JWK
	key, _ := jwk.FromRaw([]byte("test_key"))
	key.Set(jwk.KeyIDKey, "test-key-id")

	km := &MockKeyManager{jwk: key}
	server := NewServer(nil, km, nil, nil, nil) // cookie manager and provider nil

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	server.handleJWKS(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// We expect "test-key-id" in response
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	keys := resp["keys"].([]interface{})
	if len(keys) != 1 {
		t.Fatal("Expected 1 key")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	// Create mock metrics provider
	mockMetrics := &MockMetricsProvider{}

	// Create a chi router and register metrics endpoint like StartWithMiddleware does
	r := chi.NewRouter()
	metricsHandler := mockMetrics.GetPrometheusHandler()
	r.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
		metricsHandler.ServeHTTP(w, r)
	})

	// Create a test request to /metrics
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// Verify the endpoint is accessible
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify Prometheus metrics format (should contain "# HELP" or "# TYPE")
	body := w.Body.String()
	if !strings.Contains(body, "# HELP") && !strings.Contains(body, "# TYPE") {
		t.Errorf("Expected Prometheus metrics format, got: %s", body)
	}
}

func TestHandleLogin(t *testing.T) {
	cm := NewMockCookieManager()
	provider := &MockOIDCProvider{}
	server := NewServer(nil, &MockKeyManager{}, cm, provider, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/dashboard", nil)
	w := httptest.NewRecorder()

	server.handleLogin(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected status 302, got %d", w.Code)
	}

	// Verify state cookie set in mock
	state, _ := cm.GetOIDCState(req) // Mock stores it in map
	if state["return_to"] != "/dashboard" {
		t.Errorf("Expected return_to /dashboard, got %s", state["return_to"])
	}
}

func TestHandleCallback_Success(t *testing.T) {
	cm := NewMockCookieManager()
	// Pre-seed cookies
	cm.SetOIDCState(nil, nil, "/dashboard")
	cm.SetOIDCNonce(nil, nil)
	mockNonce, _ := cm.GetOIDCNonce(nil)

	// Mock OIDC responses
	token := &oauth2.Token{
		AccessToken: "test_access_token",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	token = token.WithExtra(map[string]interface{}{
		"id_token": "mock_id_token_string",
	})
	idToken := &MockIDToken{
		Nonce:   mockNonce,
		Subject: "test-user-id",
		Raw:     "mock_id_token_string",
	}

	provider := &MockOIDCProvider{
		ExchangeToken: token,
		IDToken:       idToken,
	}

	store := &MockSessionStore{}
	server := NewServer(store, &MockKeyManager{}, cm, provider, nil)

	// Construct request with valid state and code
	stateMap, _ := cm.GetOIDCState(nil)
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+stateMap["state"]+"&code=auth_code", nil)
	w := httptest.NewRecorder()

	server.handleCallback(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected status 302, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Check redirect
	loc := w.Header().Get("Location")
	if loc != "/dashboard" {
		t.Errorf("Expected redirect to /dashboard, got %s", loc)
	}

	// Check session created
	if store.lastSession == nil {
		t.Error("Expected session to be created")
	} else if store.lastSession.UserID != "test-user-id" {
		t.Errorf("Expected user ID test-user-id, got %s", store.lastSession.UserID)
	}
}

// Mock Observability Components

type MockLogger struct {
	messages []string
}

func (m *MockLogger) FromContext(ctx context.Context) interface{ Info(string, ...interface{}) } {
	return m
}

func (m *MockLogger) Info(msg string, args ...interface{}) {
	m.messages = append(m.messages, fmt.Sprintf(msg, args...))
}

type MockMetricsProvider struct {
	sessionCreatedCount int
}

func (m *MockMetricsProvider) GetPrometheusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# HELP mock_metrics Mock metrics\n"))
	})
}

func (m *MockMetricsProvider) RecordSessionCreated(ctx context.Context) {
	m.sessionCreatedCount++
}

type MockTracerProvider struct{}

func (m *MockTracerProvider) Tracer() interface{} {
	return &MockTracer{}
}

type MockTracer struct{}

type MockObservability struct {
	Logger          *MockLogger
	MetricsProvider *MockMetricsProvider
	TracerProvider  *MockTracerProvider
}

// Additional Tests

func TestNewServerWithObservability(t *testing.T) {
	// Test with nil observability
	server := NewServer(nil, &MockKeyManager{}, nil, nil, nil)
	if server.observability != nil {
		t.Error("Expected observability to be nil")
	}

	// Test that server is created successfully even without observability
	if server.sessionStore != nil {
		t.Error("Expected session store to be nil")
	}
}

func TestHandleCallback_StateMismatch(t *testing.T) {
	cm := NewMockCookieManager()
	cm.SetOIDCState(nil, nil, "/dashboard")

	provider := &MockOIDCProvider{}
	server := NewServer(nil, &MockKeyManager{}, cm, provider, nil)

	// Send wrong state
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=wrong_state&code=auth_code", nil)
	w := httptest.NewRecorder()

	server.handleCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestHandleCallback_MissingCode(t *testing.T) {
	cm := NewMockCookieManager()
	cm.SetOIDCState(nil, nil, "/dashboard")
	stateMap, _ := cm.GetOIDCState(nil)

	provider := &MockOIDCProvider{}
	server := NewServer(nil, &MockKeyManager{}, cm, provider, nil)

	// No code parameter
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+stateMap["state"], nil)
	w := httptest.NewRecorder()

	server.handleCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestHandleCallback_ExchangeError(t *testing.T) {
	cm := NewMockCookieManager()
	cm.SetOIDCState(nil, nil, "/dashboard")
	stateMap, _ := cm.GetOIDCState(nil)

	provider := &MockOIDCProvider{
		ExchangeErr: fmt.Errorf("exchange failed"),
	}
	server := NewServer(nil, &MockKeyManager{}, cm, provider, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+stateMap["state"]+"&code=auth_code", nil)
	w := httptest.NewRecorder()

	server.handleCallback(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestHandleCallback_NonceMismatch(t *testing.T) {
	cm := NewMockCookieManager()
	cm.SetOIDCState(nil, nil, "/dashboard")
	cm.SetOIDCNonce(nil, nil)
	stateMap, _ := cm.GetOIDCState(nil)

	token := &oauth2.Token{
		AccessToken: "test_access_token",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	token = token.WithExtra(map[string]interface{}{
		"id_token": "mock_id_token",
	})

	// ID token with wrong nonce
	idToken := &MockIDToken{
		Nonce:   "wrong_nonce",
		Subject: "test-user",
		Raw:     "mock_id_token",
	}

	provider := &MockOIDCProvider{
		ExchangeToken: token,
		IDToken:       idToken,
	}

	server := NewServer(nil, &MockKeyManager{}, cm, provider, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+stateMap["state"]+"&code=auth_code", nil)
	w := httptest.NewRecorder()

	server.handleCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for nonce mismatch, got %d", w.Code)
	}
}

func TestHandleCallback_OIDCError(t *testing.T) {
	server := NewServer(nil, &MockKeyManager{}, NewMockCookieManager(), &MockOIDCProvider{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied&error_description=User+denied+access", nil)
	w := httptest.NewRecorder()

	server.handleCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestHandleLogout(t *testing.T) {
	cm := NewMockCookieManager()
	cm.Encode("session_id", "test-session-id")

	store := &MockSessionStore{}
	server := NewServer(store, &MockKeyManager{}, cm, &MockOIDCProvider{}, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: "test-session-id",
	})
	w := httptest.NewRecorder()

	server.handleLogout(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check that cookie was cleared
	cookies := w.Result().Cookies()
	found := false
	for _, cookie := range cookies {
		if cookie.Name == "session_id" {
			found = true
			if cookie.Value != "" {
				t.Error("Expected session_id cookie to be cleared")
			}
			if !cookie.Expires.Before(time.Now()) {
				t.Error("Expected cookie to be expired")
			}
		}
	}
	if !found {
		t.Error("Expected session_id cookie to be set for deletion")
	}
}

func TestHandleJWKS_Error(t *testing.T) {
	km := &MockKeyManager{
		err: fmt.Errorf("key retrieval failed"),
	}
	server := NewServer(nil, km, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	server.handleJWKS(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestHandleLogin_DefaultReturnTo(t *testing.T) {
	cm := NewMockCookieManager()
	provider := &MockOIDCProvider{}
	server := NewServer(nil, &MockKeyManager{}, cm, provider, nil)

	// No return_to parameter
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()

	server.handleLogin(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected status 302, got %d", w.Code)
	}

	// Verify default return_to is "/"
	state, _ := cm.GetOIDCState(req)
	if state["return_to"] != "/" {
		t.Errorf("Expected default return_to /, got %s", state["return_to"])
	}
}

func TestHandleSessions(t *testing.T) {
	server := NewServer(nil, &MockKeyManager{}, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	w := httptest.NewRecorder()

	server.handleSessions(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("Expected status 501, got %d", w.Code)
	}
}
