// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package grpcserver

import (
	"context"
	"fmt"
	"log"
	"net"

	stsv1 "github.com/canonical/secure-token-service/api/proto/v1"
	"github.com/canonical/secure-token-service/internal/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// CookieManager defines the interface for cookie operations needed by gRPC server.
type CookieManager interface {
	Encode(name, value string) (string, error)
	Decode(name, value string) (string, error)
}

// KeyManager defines the interface for JWT token operations needed by gRPC server.
type KeyManager interface {
	MintToken(subject, issuer, audience string, expirySeconds int, claims map[string]interface{}) (string, error)
}

// Server implements the SecurityTokenService gRPC interface.
type Server struct {
	stsv1.UnimplementedSecurityTokenServiceServer
	sessionStore  *session.Store
	keyManager    KeyManager
	cookieManager CookieManager
	jwtIssuer     string
	jwtAudience   string
	jwtExpiry     int
	server        *grpc.Server
}

// NewServer creates a new gRPC server.
func NewServer(store session.Store, km KeyManager, cm CookieManager, issuer, audience string, expiry int) *Server {
	return &Server{
		sessionStore:  &store,
		keyManager:    km,
		cookieManager: cm,
		jwtIssuer:     issuer,
		jwtAudience:   audience,
		jwtExpiry:     expiry,
	}
}

// ExchangeSession swaps an opaque session_id for an internal JWT.
func (s *Server) ExchangeSession(ctx context.Context, req *stsv1.ExchangeRequest) (*stsv1.ExchangeResponse, error) {
	if req.SessionCookie == "" {
		return nil, status.Error(codes.InvalidArgument, "session_cookie is required")
	}

	// Decode session cookie
	sessID, err := s.cookieManager.Decode("session_id", req.SessionCookie)
	if err != nil {
		log.Printf("Failed to decode session cookie: %v", err)
		return nil, status.Error(codes.InvalidArgument, "invalid session cookie")
	}

	// Retrieve session from store
	sess, err := (*s.sessionStore).Get(ctx, sessID)
	if err != nil {
		log.Printf("Failed to get session %s: %v", sessID, err)
		return nil, status.Error(codes.NotFound, "session not found")
	}

	// TODO: Add custom claims from session/user profile
	claims := map[string]interface{}{
		"email": "user@example.com", // Placeholder
	}

	// Mint internal JWT
	token, err := s.keyManager.MintToken(
		sess.UserID,
		s.jwtIssuer,
		s.jwtAudience,
		s.jwtExpiry,
		claims,
	)
	if err != nil {
		log.Printf("Failed to mint token: %v", err)
		return nil, status.Error(codes.Internal, "failed to mint token")
	}

	return &stsv1.ExchangeResponse{
		AccessToken: token,
		ExpiresIn:   int64(s.jwtExpiry),
	}, nil
}

// RevokeUserSessions invalidates all sessions for a user.
func (s *Server) RevokeUserSessions(ctx context.Context, req *stsv1.RevokeUserRequest) (*stsv1.RevokeUserResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	err := (*s.sessionStore).RevokeUserSessions(ctx, req.UserId)
	if err != nil {
		log.Printf("Failed to revoke sessions for user %s: %v", req.UserId, err)
		return &stsv1.RevokeUserResponse{Success: false}, nil
	}

	return &stsv1.RevokeUserResponse{Success: true}, nil
}

// Start starts the gRPC server.
func (s *Server) Start(port string) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.server = grpc.NewServer()

	// Register the SecurityTokenService
	stsv1.RegisterSecurityTokenServiceServer(s.server, s)

	// Register reflection service for grpcurl and other tools
	reflection.Register(s.server)

	log.Printf("gRPC server listening on port %s (reflection enabled)", port)
	return s.server.Serve(listener)
}

// Stop gracefully stops the gRPC server.
func (s *Server) Stop() {
	if s.server != nil {
		s.server.GracefulStop()
	}
}
