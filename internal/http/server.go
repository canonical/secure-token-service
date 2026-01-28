package httpserver

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/canonical/secure-token-service/internal/auth"
	"github.com/canonical/secure-token-service/internal/session"
)

// Server handles HTTP endpoints for OIDC flow and JWKS.
type Server struct {
	sessionStore session.Store
	keyManager   *auth.KeyManager
}

// NewServer creates a new HTTP server.
func NewServer(store session.Store, km *auth.KeyManager) *Server {
	return &Server{
		sessionStore: store,
		keyManager:   km,
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
	return http.ListenAndServe(fmt.Sprintf(":%s", port), r)
}

// handleLogin initiates the OIDC login flow.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// TODO: Redirect to external IdP
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("Login endpoint - to be implemented"))
}

// handleCallback handles the OIDC callback.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// TODO: Exchange code for tokens, create session, set HttpOnly cookie
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("Callback endpoint - to be implemented"))
}

// handleLogout handles user logout.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// TODO: Delete session, clear cookie
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("Logout endpoint - to be implemented"))
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
