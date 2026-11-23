// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/canonical/secure-token-service/internal/constants"
	"github.com/canonical/secure-token-service/internal/cookie"
	"github.com/canonical/secure-token-service/internal/observability"
	"github.com/canonical/secure-token-service/internal/session"
)

// observabilityProvider defines the interface for observability components
type observabilityProvider interface {
	GetLogger() interface {
		FromContext(context.Context) interface{ Info(string, ...interface{}) }
	}
	GetMetricsProvider() interface {
		GetPrometheusHandler() http.Handler
		RecordSessionCreated(context.Context)
	}
	GetTracerProvider() interface{ Tracer() interface{} }
}

// ServerOption is a functional option for configuring a Server.
type ServerOption func(*Server)

// WithAllowedHosts sets the allowlist of hosts permitted in absolute return_to redirect URLs.
func WithAllowedHosts(hosts []string) ServerOption {
	return func(s *Server) {
		s.allowedHosts = append(s.allowedHosts, hosts...)
	}
}

// WithOpenIDProvider sets the OpenID provider implementation.
func WithOpenIDProvider(provider OpenIDProvider) ServerOption {
	return func(s *Server) {
		s.openIDProvider = provider
	}
}

// WithDefaultAuthProvider sets the default authentication provider ("oidc" or "openid").
func WithDefaultAuthProvider(provider string) ServerOption {
	return func(s *Server) {
		s.defaultProvider = provider
	}
}

// WithSessionExpiry sets the duration for newly created sessions.
func WithSessionExpiry(expiry time.Duration) ServerOption {
	return func(s *Server) {
		s.sessionExpiry = expiry
	}
}

// WithTenantClaim sets the OIDC ID token claim name mapped to the normalized "tenant" claim.
func WithTenantClaim(claim string) ServerOption {
	return func(s *Server) {
		s.tenantClaim = strings.TrimSpace(claim)
	}
}

// Server handles HTTP endpoints for OIDC flow, OpenID flow, and JWKS.
type Server struct {
	sessionStore    session.Store
	keyManager      KeyManager
	cookieManager   AuthCookieManager
	oidcProvider    OIDCProvider
	openIDProvider  OpenIDProvider
	defaultProvider string
	tenantClaim     string
	sessionExpiry   time.Duration
	observability   *observability.Observability
	allowedHosts    []string
	csrfProtection  *http.CrossOriginProtection
	server          *http.Server
}

const (
	defaultAuthProvider = "oidc"
	defaultTenantClaim  = "tenant"
)

// sessionLifetime returns the configured session lifetime, or the default when unset.
func (s *Server) sessionLifetime() time.Duration {
	if s.sessionExpiry <= 0 {
		return constants.DefaultSessionExpiry
	}
	return s.sessionExpiry
}

// sessionMaxAge returns the session lifetime in seconds used to validate session cookies.
func (s *Server) sessionMaxAge() int {
	return int(s.sessionLifetime().Seconds())
}

var fallbackLogger = zap.NewNop()

// logger returns the zap logger from observability, or creates a new one if not available
func (s *Server) logger(ctx context.Context) *zap.Logger {
	if s.observability != nil && s.observability.Logger != nil {
		return s.observability.Logger.FromContext(ctx)
	}
	return fallbackLogger
}

// NewServer creates a new HTTP server with optional observability and configuration options.
func NewServer(store session.Store, km KeyManager, cm AuthCookieManager, provider OIDCProvider, obs *observability.Observability, opts ...ServerOption) *Server {
	csrf := http.NewCrossOriginProtection()
	csrf.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeMeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request forbidden"})
	}))

	s := &Server{
		sessionStore:    store,
		keyManager:      km,
		cookieManager:   cm,
		oidcProvider:    provider,
		defaultProvider: defaultAuthProvider,
		tenantClaim:     defaultTenantClaim,
		observability:   obs,
		csrfProtection:  csrf,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// mountAuthAndJWKSRoutes registers all authentication and JWKS routes on the given router.
func (s *Server) mountAuthAndJWKSRoutes(r chi.Router) {
	// Auth endpoints
	r.Get("/auth/login", s.handleLogin)
	r.Get("/auth/callback", s.handleCallback)
	r.Get("/auth/openid/callback", s.handleOpenIDCallback)
	r.Get("/auth/me", s.handleMe)
	r.Get("/auth/sessions", s.handleSessions)

	// State-changing cookie-authenticated endpoints guarded by stdlib CrossOriginProtection.
	r.Group(func(r chi.Router) {
		if s.csrfProtection != nil {
			r.Use(s.csrfProtection.Handler)
		}
		r.Post("/auth/logout", s.handleLogout)
		r.Delete("/auth/sessions", s.handleRevokeAllSessions)
		r.Delete("/auth/sessions/{session_id}", s.handleRevokeSession)
	})

	// JWKS endpoint
	r.Get("/.well-known/jwks.json", s.handleJWKS)
}

// Router creates and returns a chi router with all routes configured.
// This is useful for testing endpoints.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	s.mountAuthAndJWKSRoutes(r)
	return r
}

// Start starts the HTTP server.
func (s *Server) Start(port string) error {
	r := s.Router()

	s.logger(context.Background()).Info("HTTP server starting", zap.String("port", port))
	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: r,
	}
	return s.server.ListenAndServe()
}

// StartWithMiddleware starts the HTTP server with observability middleware
func (s *Server) StartWithMiddleware(port string) error {
	r := chi.NewRouter()

	// Add observability middleware
	if s.observability != nil {
		if s.observability.Logger != nil {
			r.Use(observability.HTTPLoggingMiddleware(s.observability.Logger))
		}
		if s.observability.MetricsProvider != nil {
			r.Use(observability.HTTPMetricsMiddleware(s.observability.MetricsProvider))
		}
		if s.observability.TracerProvider != nil {
			r.Use(observability.HTTPTracingMiddleware(s.observability.TracerProvider.Tracer()))
		}
	}

	// Metrics endpoint
	if s.observability != nil && s.observability.MetricsProvider != nil {
		s.logger(context.Background()).Info("Metrics endpoint enabled", zap.String("port", port))
		// Wrap the http.Handler to make it compatible with r.Get which expects http.HandlerFunc
		metricsHandler := s.observability.MetricsProvider.GetPrometheusHandler()
		r.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
			s.logger(r.Context()).Info("Metrics endpoint hit", zap.String("port", port))
			metricsHandler.ServeHTTP(w, r)
		})
	}

	// Homepage
	r.Get("/", s.handleHome)

	s.mountAuthAndJWKSRoutes(r)

	s.logger(context.Background()).Info("HTTP server starting with middleware", zap.String("port", port))
	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: r,
	}
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// isSecureRequest checks whether the incoming request used TLS or was forwarded as HTTPS.
func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// isValidReturnTo validates that returnTo is a safe redirect target to prevent open redirect vulnerabilities.
func (s *Server) isValidReturnTo(returnTo string, reqHost string) bool {
	// Empty string defaults to "/" (valid).
	if returnTo == "" {
		return true
	}

	// Reject control characters (\r, \n, null bytes, CRLF injection).
	for _, r := range returnTo {
		if unicode.IsControl(r) {
			return false
		}
	}

	// Reject backslash evasions (starting with "/\", "\\", "/\\", or containing "\").
	if strings.HasPrefix(returnTo, "/\\") || strings.Contains(returnTo, "\\") {
		return false
	}

	// Reject scheme-relative redirects (starting with "//", "///", etc.).
	if strings.HasPrefix(returnTo, "//") {
		return false
	}

	// Parse URL with url.Parse(returnTo).
	u, err := url.Parse(returnTo)
	if err != nil {
		return false
	}

	// If relative path (empty scheme and host): must start with "/" (path-relative),
	// and must not have '/' or '\' in its second position.
	if u.Scheme == "" {
		if u.Host != "" {
			return false
		}
		if len(returnTo) > 1 && (returnTo[1] == '/' || returnTo[1] == '\\') {
			return false
		}
		return strings.HasPrefix(returnTo, "/")
	}

	// If absolute URL with http/https scheme: allowed if host matches reqHost or configured allowed hosts.
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		// Reject dangerous schemes (javascript:, data:, vbscript:, etc.).
		return false
	}

	if u.User != nil {
		return false
	}

	if u.Host == "" {
		return false
	}

	uHostname := u.Hostname()

	if reqHost != "" && matchHost(u.Host, uHostname, reqHost) {
		return true
	}

	for _, allowed := range s.allowedHosts {
		trimmed := strings.TrimSpace(allowed)
		if trimmed != "" && matchHost(u.Host, uHostname, trimmed) {
			return true
		}
	}

	return false
}

func matchHost(targetHost, targetHostname, allowed string) bool {
	if strings.Contains(allowed, ":") {
		return strings.EqualFold(targetHost, allowed)
	}
	return strings.EqualFold(targetHostname, allowed) || strings.EqualFold(targetHost, allowed)
}

// handleLogin initiates the authentication flow with the selected provider.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// 1. Get return_to URL
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}
	if !s.isValidReturnTo(returnTo, r.Host) {
		s.logger(r.Context()).Warn("invalid return_to parameter", zap.String("return_to", returnTo))
		http.Error(w, "Invalid return_to parameter", http.StatusBadRequest)
		return
	}

	// 2. Determine provider
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		if s.defaultProvider != "" {
			provider = s.defaultProvider
		} else {
			provider = defaultAuthProvider
		}
	}

	switch provider {
	case "oidc":
		if s.oidcProvider == nil {
			s.logger(r.Context()).Error("OIDC provider not configured")
			http.Error(w, "OIDC provider not configured", http.StatusInternalServerError)
			return
		}

		// Generate and store state
		state, err := s.cookieManager.SetAuthState(w, r, cookie.AuthState{
			ReturnTo: returnTo,
			Provider: "oidc",
		})
		if err != nil {
			s.logger(r.Context()).Error("failed to generate state", zap.Error(err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Generate and store nonce
		nonce, err := s.cookieManager.SetOIDCNonce(w, r)
		if err != nil {
			s.logger(r.Context()).Error("failed to generate nonce", zap.Error(err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Redirect to OIDC provider
		http.Redirect(w, r, s.oidcProvider.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)

	case "openid":
		if s.openIDProvider == nil {
			s.logger(r.Context()).Error("openid provider not configured")
			http.Error(w, "OpenID provider not configured", http.StatusInternalServerError)
			return
		}

		// Generate and store state
		state, err := s.cookieManager.SetAuthState(w, r, cookie.AuthState{
			ReturnTo: returnTo,
			Provider: "openid",
		})
		if err != nil {
			s.logger(r.Context()).Error("failed to generate state", zap.Error(err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// OpenID return_to URL pointing to /auth/openid/callback
		scheme := "http"
		if isSecureRequest(r) {
			scheme = "https"
		}
		returnToCallback := fmt.Sprintf("%s://%s/auth/openid/callback", scheme, r.Host)

		authURL, err := s.openIDProvider.BuildAuthURL(returnToCallback, state)
		if err != nil {
			s.logger(r.Context()).Error("failed to build OpenID auth URL", zap.Error(err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, authURL, http.StatusFound)

	default:
		s.logger(r.Context()).Warn("unsupported auth provider", zap.String("provider", provider))
		http.Error(w, fmt.Sprintf("Unsupported provider: %s", provider), http.StatusBadRequest)
		return
	}
}

// handleCallback handles the OIDC callback.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// 0. Check for OIDC errors
	if oidcError := r.URL.Query().Get("error"); oidcError != "" {
		if s.cookieManager != nil {
			s.cookieManager.ClearAuthState(w, r)
		}
		description := r.URL.Query().Get("error_description")
		s.logger(r.Context()).Error("OIDC login failed",
			zap.String("error", oidcError),
			zap.String("description", description))
		http.Error(w, fmt.Sprintf("Login failed: %s", oidcError), http.StatusBadRequest)
		return
	}

	// 1. Verify state
	stateData, err := s.cookieManager.GetAuthState(r)
	if err != nil {
		s.logger(r.Context()).Error("state verification failed", zap.Error(err))
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != stateData.State {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	if stateData.Provider != "" && stateData.Provider != "oidc" {
		http.Error(w, "Provider mismatch", http.StatusBadRequest)
		return
	}

	s.cookieManager.ClearAuthState(w, r)

	// 2. Exchange code
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}

	oauth2Token, err := s.oidcProvider.Exchange(r.Context(), code)
	if err != nil {
		s.logger(r.Context()).Error("failed to exchange token", zap.Error(err))
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// 3. Extract and Verify ID Token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token", http.StatusInternalServerError)
		return
	}

	idToken, err := s.oidcProvider.VerifyIDToken(r.Context(), rawIDToken)
	if err != nil {
		s.logger(r.Context()).Error("failed to verify ID token", zap.Error(err))
		http.Error(w, "Failed to verify ID Token", http.StatusInternalServerError)
		return
	}

	// 4. Verify Nonce
	nonce, err := s.cookieManager.GetOIDCNonce(r)
	if err != nil {
		s.logger(r.Context()).Error("nonce verification failed", zap.Error(err))
		http.Error(w, "Invalid nonce", http.StatusBadRequest)
		return
	}
	s.cookieManager.ClearOIDCNonce(w, r)

	idTokenNonce, err := idToken.GetNonce()
	if err != nil || idTokenNonce != nonce {
		http.Error(w, "Nonce mismatch", http.StatusBadRequest)
		return
	}

	// 5. Create Session
	var rawClaims map[string]interface{}
	if err := idToken.Claims(&rawClaims); err != nil {
		s.logger(r.Context()).Error("failed to extract ID token claims", zap.Error(err))
		http.Error(w, "Failed to extract user ID from ID Token", http.StatusInternalServerError)
		return
	}

	normalizedClaims, userID := s.normalizeOIDCClaims(r.Context(), rawClaims)
	if userID == "" {
		http.Error(w, "Failed to extract user ID from ID Token", http.StatusInternalServerError)
		return
	}

	sessionID := uuid.New().String()
	now := time.Now().UTC()
	expiresAt := now.Add(s.sessionLifetime())
	sess := &session.Session{
		SessionID:    sessionID,
		UserID:       userID,
		Provider:     "oidc",
		Claims:       normalizedClaims,
		AccessToken:  oauth2Token.AccessToken(),
		IDToken:      idToken.GetOriginalToken(),
		RefreshToken: oauth2Token.RefreshToken(),
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
	}

	if err := s.sessionStore.Set(r.Context(), sess); err != nil {
		s.logger(r.Context()).Error("failed to save session", zap.Error(err))
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	s.recordSessionCreated(r.Context())

	// 6. Set Session Cookie
	// The cookie outlives the upstream access token; the session store enforces expiry.
	if err := s.cookieManager.SetSessionCookie(w, r, sessionID, expiresAt); err != nil {
		s.logger(r.Context()).Error("failed to set session cookie", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	s.cleanupReplacedSession(r, sessionID)

	// 7. Redirect to return_to
	returnTo := stateData.ReturnTo
	if returnTo == "" || !s.isValidReturnTo(returnTo, r.Host) {
		if returnTo != "" {
			s.logger(r.Context()).Warn("invalid return_to parameter; falling back to /", zap.String("return_to", returnTo))
		}
		returnTo = "/"
	}

	http.Redirect(w, r, returnTo, http.StatusFound)
}

// handleOpenIDCallback handles the Ubuntu One OpenID 2.0 authentication callback.
func (s *Server) handleOpenIDCallback(w http.ResponseWriter, r *http.Request) {
	// 0. Check for user cancellation or errors
	if r.URL.Query().Get("openid.mode") == "cancel" {
		if s.cookieManager != nil {
			s.cookieManager.ClearAuthState(w, r)
		}
		s.logger(r.Context()).Warn("OpenID authentication cancelled by user")
		http.Error(w, "Login cancelled", http.StatusBadRequest)
		return
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		if s.cookieManager != nil {
			s.cookieManager.ClearAuthState(w, r)
		}
		s.logger(r.Context()).Error("OpenID login failed with error", zap.String("error", errParam))
		http.Error(w, fmt.Sprintf("Login failed: %s", errParam), http.StatusBadRequest)
		return
	}

	if s.openIDProvider == nil {
		s.logger(r.Context()).Error("OpenID provider not configured")
		http.Error(w, "OpenID provider not configured", http.StatusInternalServerError)
		return
	}

	// 1. Verify state cookie
	stateData, err := s.cookieManager.GetAuthState(r)
	if err != nil {
		s.logger(r.Context()).Error("state verification failed", zap.Error(err))
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != stateData.State {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	if stateData.Provider != "openid" {
		http.Error(w, "Provider mismatch", http.StatusBadRequest)
		return
	}

	s.cookieManager.ClearAuthState(w, r)

	// 2. Direct verification with OpenID Provider (check_authentication)
	scheme := "http"
	if isSecureRequest(r) {
		scheme = "https"
	}
	cbURL := &url.URL{
		Scheme: scheme,
		Host:   r.Host,
		Path:   "/auth/openid/callback",
	}
	if stateData.State != "" {
		q := cbURL.Query()
		q.Set("state", stateData.State)
		cbURL.RawQuery = q.Encode()
	}
	expectedReturnTo := cbURL.String()

	claims, err := s.openIDProvider.VerifyCallback(r.Context(), r, expectedReturnTo)
	if err != nil {
		s.logger(r.Context()).Error("failed to verify OpenID callback", zap.Error(err))
		http.Error(w, "OpenID verification failed", http.StatusBadRequest)
		return
	}

	// 3. Extract user ID
	userID, err := claims.UserID()
	if err != nil || userID == "" {
		s.logger(r.Context()).Error("failed to extract user ID from OpenID claims", zap.Error(err))
		http.Error(w, "Failed to extract user ID from claims", http.StatusBadRequest)
		return
	}

	if claims.Email != "" {
		s.logger(r.Context()).Info("OpenID authenticated user",
			zap.String("user_id", userID),
			zap.String("email", claims.Email),
			zap.String("claimed_id", claims.ClaimedID))
	} else {
		s.logger(r.Context()).Warn("OpenID callback missing email attribute",
			zap.String("user_id", userID),
			zap.String("claimed_id", claims.ClaimedID))
	}

	// 4. Create session
	sessionID := uuid.New().String()
	now := time.Now().UTC()
	expiresAt := now.Add(s.sessionLifetime())

	sess := &session.Session{
		SessionID: sessionID,
		UserID:    userID,
		Provider:  "openid",
		Claims:    claims.NormalizedClaims(),
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}

	if err := s.sessionStore.Set(r.Context(), sess); err != nil {
		s.logger(r.Context()).Error("failed to save session", zap.Error(err))
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	s.recordSessionCreated(r.Context())

	// 5. Set Session Cookie
	if err := s.cookieManager.SetSessionCookie(w, r, sessionID, sess.ExpiresAt); err != nil {
		s.logger(r.Context()).Error("failed to set session cookie", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	s.cleanupReplacedSession(r, sessionID)

	// 6. Redirect to return_to
	returnTo := stateData.ReturnTo
	if returnTo == "" || !s.isValidReturnTo(returnTo, r.Host) {
		if returnTo != "" {
			s.logger(r.Context()).Warn("invalid return_to parameter; falling back to /", zap.String("return_to", returnTo))
		}
		returnTo = "/"
	}

	http.Redirect(w, r, returnTo, http.StatusFound)
}

// handleLogout handles user logout.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		// Attempt to decode to get session ID for deletion from store
		if sessionID, err := s.cookieManager.Decode("session_id", cookie.Value, s.sessionMaxAge()); err == nil {
			if err := s.sessionStore.Delete(r.Context(), sessionID); err != nil {
				s.logger(r.Context()).Error("failed to delete session",
					zap.String("session_id", sessionID),
					zap.Error(err))
			}
		}
	}

	// Clear cookie using standardized CookieManager
	s.cookieManager.ClearSessionCookie(w, r)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged out"))
}

type sessionMetadata struct {
	SessionID string    `json:"session_id"`
	Provider  string    `json:"provider"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IsCurrent bool      `json:"is_current"`
}

type sessionsListResponse struct {
	Sessions []sessionMetadata `json:"sessions"`
}

type revokeSessionResponse struct {
	Revoked bool `json:"revoked"`
}

type revokeSessionsResponse struct {
	RevokedCount int `json:"revoked_count"`
}

func (s *Server) recordSessionCreated(ctx context.Context) {
	if s.observability != nil && s.observability.MetricsProvider != nil {
		s.observability.MetricsProvider.RecordSessionCreated(ctx)
	}
}

// cleanupReplacedSession best-effort deletes an existing valid session_id cookie's
// backing session when a browser re-authenticates or switches providers, preventing
// orphaned duplicate sessions in GET /auth/sessions.
func (s *Server) cleanupReplacedSession(r *http.Request, newSessionID string) {
	if s.cookieManager == nil || s.sessionStore == nil {
		return
	}
	ck, err := r.Cookie("session_id")
	if err != nil || ck.Value == "" {
		return
	}
	oldSessionID, err := s.cookieManager.Decode("session_id", ck.Value, s.sessionMaxAge())
	if err != nil || oldSessionID == "" || oldSessionID == newSessionID {
		return
	}
	if err := s.sessionStore.Delete(r.Context(), oldSessionID); err != nil && !errors.Is(err, session.ErrSessionNotFound) {
		s.logger(r.Context()).Warn("failed to delete replaced session on re-authentication",
			zap.String("session_id", oldSessionID),
			zap.Error(err))
	}
}

// resolveCallerSession validates the caller's session_id cookie and resolves the active session.
// On failure it returns an HTTP status code (401, 500, or 503) and error message without writing to w.
func (s *Server) resolveCallerSession(r *http.Request) (string, *session.Session, int, string) {
	if s.cookieManager == nil || s.sessionStore == nil {
		return "", nil, http.StatusInternalServerError, "internal server error"
	}

	ck, err := r.Cookie("session_id")
	if err != nil || ck.Value == "" {
		return "", nil, http.StatusUnauthorized, "unauthorized"
	}

	sessionID, err := s.cookieManager.Decode("session_id", ck.Value, s.sessionMaxAge())
	if err != nil || sessionID == "" {
		return "", nil, http.StatusUnauthorized, "unauthorized"
	}

	sess, err := s.sessionStore.Get(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			return "", nil, http.StatusUnauthorized, "unauthorized"
		}
		s.logger(r.Context()).Error("failed to get caller session", zap.Error(err))
		return "", nil, http.StatusServiceUnavailable, "session store unavailable"
	}
	if sess == nil {
		return "", nil, http.StatusUnauthorized, "unauthorized"
	}

	return sessionID, sess, http.StatusOK, ""
}

// authenticateSessionCookie validates the caller's session_id cookie and resolves the active session.
// On failure it writes the appropriate JSON error response (401, 500, or 503) and returns ok=false.
func (s *Server) authenticateSessionCookie(w http.ResponseWriter, r *http.Request) (string, *session.Session, bool) {
	sessionID, sess, statusCode, errMsg := s.resolveCallerSession(r)
	if statusCode != http.StatusOK {
		writeMeJSON(w, statusCode, map[string]string{"error": errMsg})
		return "", nil, false
	}
	return sessionID, sess, true
}

// handleSessions lists all active sessions owned by the authenticated caller.
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	currentSessionID, callerSess, ok := s.authenticateSessionCookie(w, r)
	if !ok {
		return
	}

	activeSessions, err := s.sessionStore.ListUserSessions(r.Context(), callerSess.UserID)
	if err != nil {
		s.logger(r.Context()).Error("failed to list user sessions",
			zap.String("user_id", callerSess.UserID),
			zap.Error(err))
		writeMeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "session store unavailable"})
		return
	}

	items := make([]sessionMetadata, 0, len(activeSessions))
	for _, sess := range activeSessions {
		if sess == nil {
			continue
		}
		items = append(items, sessionMetadata{
			SessionID: sess.SessionID,
			Provider:  sess.Provider,
			CreatedAt: sess.CreatedAt,
			ExpiresAt: sess.ExpiresAt,
			IsCurrent: sess.SessionID == currentSessionID,
		})
	}

	writeMeJSON(w, http.StatusOK, sessionsListResponse{Sessions: items})
}

// handleRevokeSession revokes a single session owned by the authenticated caller.
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	currentSessionID, callerSess, ok := s.authenticateSessionCookie(w, r)
	if !ok {
		return
	}

	targetID := strings.TrimSpace(chi.URLParam(r, "session_id"))
	if targetID == "" {
		writeMeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	if err := s.sessionStore.DeleteUserSession(r.Context(), callerSess.UserID, targetID); err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			s.logger(r.Context()).Warn("rejected session revocation for missing or non-owned session",
				zap.String("user_id", callerSess.UserID),
				zap.String("session_id", targetID),
				zap.String("outcome", "not_found"))
			writeMeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
			return
		}
		s.logger(r.Context()).Error("failed to delete target session",
			zap.String("user_id", callerSess.UserID),
			zap.String("session_id", targetID),
			zap.Error(err))
		writeMeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "session store unavailable"})
		return
	}

	isCurrent := targetID == currentSessionID
	if isCurrent {
		s.cookieManager.ClearSessionCookie(w, r)
	}

	s.logger(r.Context()).Info("session revoked",
		zap.String("user_id", callerSess.UserID),
		zap.String("session_id", targetID),
		zap.Bool("is_current", isCurrent),
		zap.String("outcome", "revoked"))

	writeMeJSON(w, http.StatusOK, revokeSessionResponse{Revoked: true})
}

// handleRevokeAllSessions revokes all sessions owned by the authenticated caller,
// optionally preserving the caller's current session when ?exclude_current=true.
func (s *Server) handleRevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	currentSessionID, callerSess, ok := s.authenticateSessionCookie(w, r)
	if !ok {
		return
	}

	excludeCurrent := false
	if r.URL.Query().Has("exclude_current") {
		parsed, err := strconv.ParseBool(r.URL.Query().Get("exclude_current"))
		if err != nil {
			writeMeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid exclude_current query parameter"})
			return
		}
		excludeCurrent = parsed
	}

	keepSessionID := ""
	if excludeCurrent {
		keepSessionID = currentSessionID
	}

	revokedCount, err := s.sessionStore.RevokeUserSessionsExcept(r.Context(), callerSess.UserID, keepSessionID)
	if err != nil {
		s.logger(r.Context()).Error("failed to revoke user sessions",
			zap.String("user_id", callerSess.UserID),
			zap.Bool("exclude_current", excludeCurrent),
			zap.Error(err))
		writeMeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "session store unavailable"})
		return
	}

	if !excludeCurrent {
		s.cookieManager.ClearSessionCookie(w, r)
	}

	s.logger(r.Context()).Info("user sessions revoked",
		zap.String("user_id", callerSess.UserID),
		zap.Int("revoked_count", revokedCount),
		zap.Bool("exclude_current", excludeCurrent),
		zap.String("outcome", "revoked"))

	writeMeJSON(w, http.StatusOK, revokeSessionsResponse{RevokedCount: revokedCount})
}

type meResponse struct {
	Authenticated bool    `json:"authenticated"`
	User          *meUser `json:"user,omitempty"`
}

type meUser struct {
	ID     string `json:"id"`
	Email  string `json:"email,omitempty"`
	Name   string `json:"name,omitempty"`
	Tenant string `json:"tenant,omitempty"`
}

func (s *Server) effectiveTenantClaim() string {
	if s.tenantClaim != "" {
		return s.tenantClaim
	}
	return defaultTenantClaim
}

func stringClaim(raw map[string]interface{}, key string) string {
	if raw == nil {
		return ""
	}
	val, ok := raw[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(val)
}

func (s *Server) normalizeOIDCClaims(ctx context.Context, raw map[string]interface{}) (map[string]interface{}, string) {
	claims := make(map[string]interface{})

	sub := stringClaim(raw, "sub")
	email := stringClaim(raw, "email")
	// Verify email_verified before promoting email to UserID or normalized claims.
	//
	// Why: Session.UserID is the authorization key for `user_sessions:<UserID>` in
	// GET/DELETE /auth/sessions and the primary `sub` in ExchangeSession JWTs.
	// Trusting an unverified OIDC email claim (`email_verified: false`) would allow
	// account/session squatting: an attacker with an unverified email matching a
	// victim's address could list or revoke the victim's sessions and mint internal
	// JWTs with the victim's identity.
	//
	// Policy:
	// - When `email_verified` is present, accept boolean `true` or case-insensitive
	//   string `"true"` (for federated IdPs that stringify booleans); any other value
	//   (false, "false", nil, etc.) causes `email` to be treated as unverified and omitted.
	// - When `email_verified` is omitted entirely, `email` remains usable because
	//   Canonical's Ory Kratos + identity-platform-login-ui stack (`social_user_v0.json`
	//   + `GetUserClaims`) does not store `email_verified` in Kratos `traits` and thus
	//   omits `email_verified` from minted ID tokens.
	if rawVerified, hasVerified := raw["email_verified"]; hasVerified {
		verified := false
		switch v := rawVerified.(type) {
		case bool:
			verified = v
		case string:
			verified = strings.EqualFold(strings.TrimSpace(v), "true")
		}
		if !verified {
			s.logger(ctx).Warn("ignoring unverified OIDC email claim for UserID and normalized claims")
			email = ""
		}
	}
	givenName := stringClaim(raw, "given_name")
	familyName := stringClaim(raw, "family_name")
	name := stringClaim(raw, "name")
	if name == "" && (givenName != "" || familyName != "") {
		name = strings.TrimSpace(givenName + " " + familyName)
	}
	preferredUsername := stringClaim(raw, "preferred_username")
	nickname := stringClaim(raw, "nickname")

	if sub != "" {
		claims["sub"] = sub
	}
	if email != "" {
		claims["email"] = email
	}
	if name != "" {
		claims["name"] = name
	}
	if givenName != "" {
		claims["given_name"] = givenName
	}
	if preferredUsername != "" {
		claims["preferred_username"] = preferredUsername
	}
	if nickname != "" {
		claims["nickname"] = nickname
	}

	tenantKey := s.effectiveTenantClaim()
	if rawVal, exists := raw[tenantKey]; exists {
		if tenantStr, ok := rawVal.(string); ok {
			if trimmed := strings.TrimSpace(tenantStr); trimmed != "" {
				claims["tenant"] = trimmed
			}
		} else if rawVal != nil {
			s.logger(ctx).Debug("ignoring non-string OIDC tenant claim", zap.String("claim", tenantKey))
		}
	}

	claims["idp_provider"] = "oidc"

	// Resolve OIDC UserID strictly from verified email or immutable `sub` (prefixed
	// with `oidc:` so it cannot collide with emails or OpenID handles). Never fall back
	// to `nickname` or `preferred_username`, which are unverified and mutable (OIDC Core §5.1/§5.7).
	userID := email
	if userID == "" && sub != "" {
		userID = "oidc:" + sub
	}

	return claims, userID
}

func writeMeJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Cookie")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

// handleMe returns minimal public user identity for the active session cookie.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	_, sess, statusCode, errMsg := s.resolveCallerSession(r)
	if statusCode != http.StatusOK {
		if statusCode == http.StatusUnauthorized {
			writeMeJSON(w, http.StatusUnauthorized, meResponse{Authenticated: false})
			return
		}
		writeMeJSON(w, statusCode, map[string]string{"error": errMsg})
		return
	}

	user := &meUser{
		ID: sess.UserID,
	}
	if email := stringClaim(sess.Claims, "email"); email != "" {
		user.Email = email
	}
	if name := stringClaim(sess.Claims, "name"); name != "" {
		user.Name = name
	}
	if tenant := stringClaim(sess.Claims, "tenant"); tenant != "" {
		user.Tenant = tenant
	}

	writeMeJSON(w, http.StatusOK, meResponse{
		Authenticated: true,
		User:          user,
	})
}

// handleJWKS exposes the public key for JWT verification.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	// Get all public keys (active + retired) from key manager with caching
	set, err := s.keyManager.GetAllJWKS()
	if err != nil {
		s.logger(r.Context()).Error("failed to get JWKS", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set HTTP cache headers (browser/CDN caching)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", constants.HTTPCacheMaxAge))
	w.Header().Set("Content-Type", "application/json")

	// Marshal the JWK Set to JSON
	if err := json.NewEncoder(w).Encode(set); err != nil {
		s.logger(r.Context()).Error("failed to encode JWKS", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}
