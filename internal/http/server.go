// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/canonical/secure-token-service/internal/session"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Server handles HTTP endpoints for OIDC flow and JWKS.
// Server handles HTTP endpoints for OIDC flow and JWKS.
type Server struct {
	sessionStore  session.Store
	keyManager    KeyManager
	cookieManager AuthCookieManager
	oidcProvider  OIDCProvider
	server        *http.Server
}

// NewServer creates a new HTTP server.
func NewServer(store session.Store, km KeyManager, cm AuthCookieManager, provider OIDCProvider) *Server {
	return &Server{
		sessionStore:  store,
		keyManager:    km,
		cookieManager: cm,
		oidcProvider:  provider,
	}
}

// Start starts the HTTP server.
func (s *Server) Start(port string) error {
	r := chi.NewRouter()

	// OIDC endpoints (stubs for now)
	r.Get("/auth/login", s.handleLogin)
	r.Get("/auth/callback", s.handleCallback)
	r.Post("/auth/logout", s.handleLogout)
	r.Get("/auth/sessions", s.handleSessions)

	// JWKS endpoint
	r.Get("/.well-known/jwks.json", s.handleJWKS)

	log.Printf("HTTP server listening on port %s", port)
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
		log.Printf("Failed to generate state: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 3. Generate and store nonce
	nonce, err := s.cookieManager.SetOIDCNonce(w, r)
	if err != nil {
		log.Printf("Failed to generate nonce: %v", err)
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
		log.Printf("OIDC login failed: %s - %s", oidcError, description)
		http.Error(w, fmt.Sprintf("Login failed: %s", oidcError), http.StatusBadRequest)
		return
	}

	// 1. Verify state
	stateData, err := s.cookieManager.GetOIDCState(r)
	if err != nil {
		log.Printf("State verification failed: %v", err)
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
		log.Printf("Failed to exchange token: %v", err)
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
		log.Printf("Nonce verification failed: %v", err)
		http.Error(w, "Invalid nonce", http.StatusBadRequest)
		return
	}
	s.cookieManager.ClearOIDCNonce(w, r)

	if idToken.GetNonce() != nonce {
		http.Error(w, "Nonce mismatch", http.StatusBadRequest)
		return
	}

	// 5. Create Session
	sessionID := uuid.New().String()
	// Ideally extract sub from idToken for userID
	userID := idToken.GetSubject()
	if userID == "" {
		userID = "user-" + sessionID
	}

	now := time.Now()
	sess := &session.Session{
		SessionID:    sessionID,
		UserID:       userID,
		AccessToken:  oauth2Token.AccessToken,
		IDToken:      idToken.GetOriginalToken(),
		RefreshToken: oauth2Token.RefreshToken,
		ExpiresAt:    oauth2Token.Expiry,
		CreatedAt:    now,
	}

	if sess.ExpiresAt.IsZero() {
		sess.ExpiresAt = now.Add(1 * time.Hour)
	}

	if err := s.sessionStore.Set(r.Context(), sess); err != nil {
		log.Printf("Failed to save session: %v", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// 6. Set Session Cookie
	encodedSession, err := s.cookieManager.Encode("session_id", sessionID)
	if err != nil {
		log.Printf("Failed to encode session cookie: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    encodedSession,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
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
				log.Printf("Failed to delete session %s: %v", sessionID, err)
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
	key, err := s.keyManager.GetJWK()
	if err != nil {
		log.Printf("Failed to get JWK: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create a JWK Set containing the public key
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		log.Printf("Failed to add key to set: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Marshal the JWK Set to JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(set); err != nil {
		log.Printf("Failed to encode JWKS: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}
