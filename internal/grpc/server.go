package grpcserver

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/canonical/secure-token-service/internal/auth"
	"github.com/canonical/secure-token-service/internal/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the SecurityTokenService gRPC interface.
type Server struct {
	// UnimplementedSecurityTokenServiceServer
	sessionStore *session.Store
	keyManager   *auth.KeyManager
	jwtIssuer    string
	jwtAudience  string
	jwtExpiry    int
}

// NewServer creates a new gRPC server.
func NewServer(store session.Store, km *auth.KeyManager, issuer, audience string, expiry int) *Server {
	return &Server{
		sessionStore: &store,
		keyManager:   km,
		jwtIssuer:    issuer,
		jwtAudience:  audience,
		jwtExpiry:    expiry,
	}
}

// ExchangeSession swaps an opaque session_id for an internal JWT.
func (s *Server) ExchangeSession(ctx context.Context, req *ExchangeRequest) (*ExchangeResponse, error) {
	if req.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}

	// Retrieve session from store
	sess, err := (*s.sessionStore).Get(ctx, req.SessionId)
	if err != nil {
		log.Printf("Failed to get session %s: %v", req.SessionId, err)
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

	return &ExchangeResponse{
		AccessToken: token,
		ExpiresIn:   int64(s.jwtExpiry),
	}, nil
}

// RevokeUserSessions invalidates all sessions for a user.
func (s *Server) RevokeUserSessions(ctx context.Context, req *RevokeUserRequest) (*RevokeUserResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	err := (*s.sessionStore).RevokeUserSessions(ctx, req.UserId)
	if err != nil {
		log.Printf("Failed to revoke sessions for user %s: %v", req.UserId, err)
		return &RevokeUserResponse{Success: false}, nil
	}

	return &RevokeUserResponse{Success: true}, nil
}

// Start starts the gRPC server.
func (s *Server) Start(port string) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	grpcServer := grpc.NewServer()
	// TODO: Register the service once proto is generated
	// RegisterSecurityTokenServiceServer(grpcServer, s)

	log.Printf("gRPC server listening on port %s", port)
	return grpcServer.Serve(listener)
}

// Placeholder types until proto is generated
type ExchangeRequest struct {
	SessionId string
}

type ExchangeResponse struct {
	AccessToken string
	ExpiresIn   int64
}

type RevokeUserRequest struct {
	UserId string
}

type RevokeUserResponse struct {
	Success bool
}
