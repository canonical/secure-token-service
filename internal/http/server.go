// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/canonical/secure-token-service/internal/constants"
	"github.com/canonical/secure-token-service/internal/observability"
	"github.com/canonical/secure-token-service/internal/session"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
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

// Server handles HTTP endpoints for OIDC flow and JWKS.
type Server struct {
	sessionStore  session.Store
	keyManager    KeyManager
	cookieManager AuthCookieManager
	oidcProvider  OIDCProvider
	observability *observability.Observability
	server        *http.Server
}

// logger returns the zap logger from observability, or creates a new one if not available
func (s *Server) logger(ctx context.Context) *zap.Logger {
	if s.observability != nil && s.observability.Logger != nil {
		return s.observability.Logger.FromContext(ctx)
	}
	// Return a new logger if observability is not set up
	logger, err := observability.NewLogger("info", false)
	if err != nil {
		return zap.NewNop()
	}
	return logger.Logger
}

// NewServer creates a new HTTP server with optional observability.
func NewServer(store session.Store, km KeyManager, cm AuthCookieManager, provider OIDCProvider, obs *observability.Observability) *Server {
	return &Server{
		sessionStore:  store,
		keyManager:    km,
		cookieManager: cm,
		oidcProvider:  provider,
		observability: obs,
	}
}

// Router creates and returns a chi router with all routes configured.
// This is useful for testing endpoints.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	// OIDC endpoints
	r.Get("/auth/login", s.handleLogin)
	r.Get("/auth/callback", s.handleCallback)
	r.Post("/auth/logout", s.handleLogout)
	r.Get("/auth/sessions", s.handleSessions)

	// JWKS endpoint
	r.Get("/.well-known/jwks.json", s.handleJWKS)

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

	// OIDC endpoints
	r.Get("/auth/login", s.handleLogin)
	r.Get("/auth/callback", s.handleCallback)
	r.Post("/auth/logout", s.handleLogout)
	r.Get("/auth/sessions", s.handleSessions)

	// JWKS endpoint
	r.Get("/.well-known/jwks.json", s.handleJWKS)

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

// handleLogin initiates the OIDC login flow.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// 1. Get return_to URL
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}

	// 2. Generate and store state
	state, err := s.cookieManager.SetOIDCState(w, r, returnTo)
	if err != nil {
		s.logger(r.Context()).Error("failed to generate state", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 3. Generate and store nonce
	nonce, err := s.cookieManager.SetOIDCNonce(w, r)
	if err != nil {
		s.logger(r.Context()).Error("failed to generate nonce", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 4. Redirect to OIDC provider
	http.Redirect(w, r, s.oidcProvider.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

// handleCallback handles the OIDC callback.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// 0. Check for OIDC errors
	if oidcError := r.URL.Query().Get("error"); oidcError != "" {
		description := r.URL.Query().Get("error_description")
		s.logger(r.Context()).Error("OIDC login failed",
			zap.String("error", oidcError),
			zap.String("description", description))
		http.Error(w, fmt.Sprintf("Login failed: %s", oidcError), http.StatusBadRequest)
		return
	}

	// 1. Verify state
	stateData, err := s.cookieManager.GetOIDCState(r)
	if err != nil {
		s.logger(r.Context()).Error("state verification failed", zap.Error(err))
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	s.cookieManager.ClearOIDCState(w, r)

	if r.URL.Query().Get("state") != stateData["state"] {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

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
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
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
	sessionID := uuid.New().String()
	// Ideally extract sub from idToken for userID
	userID, err := idToken.GetSubject()
	if err != nil || userID == "" {
		userID = "user-" + sessionID
	}

	now := time.Now()
	sess := &session.Session{
		SessionID:    sessionID,
		UserID:       userID,
		AccessToken:  oauth2Token.AccessToken(),
		IDToken:      idToken.GetOriginalToken(),
		RefreshToken: oauth2Token.RefreshToken(),
		ExpiresAt:    oauth2Token.Expiry(),
		CreatedAt:    now,
	}

	if err := s.sessionStore.Set(r.Context(), sess); err != nil {
		s.logger(r.Context()).Error("failed to save session", zap.Error(err))
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// 6. Set Session Cookie
	encodedSession, err := s.cookieManager.Encode("session_id", sessionID)
	if err != nil {
		s.logger(r.Context()).Error("failed to encode session cookie", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    encodedSession,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
	})

	// 7. Redirect to return_to
	http.Redirect(w, r, stateData["return_to"], http.StatusFound)
}

// Helpers removed - logic moved to CookieManager

// handleLogout handles user logout.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		// Attempt to decode to get session ID for deletion from store
		if sessionID, err := s.cookieManager.Decode("session_id", cookie.Value); err == nil {
			if err := s.sessionStore.Delete(r.Context(), sessionID); err != nil {
				s.logger(r.Context()).Error("failed to delete session",
					zap.String("session_id", sessionID),
					zap.Error(err))
			}
		}
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged out"))
}

// handleSessions lists active sessions (admin endpoint).
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	// TODO: List sessions for admin/debugging
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("Sessions endpoint - to be implemented"))
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
