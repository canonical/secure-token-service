// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package grpcserver

import (
	"context"
	"fmt"
	"net"
	"strings"

	stsv1 "github.com/canonical/secure-token-service/api/proto/v1"
	"github.com/canonical/secure-token-service/internal/observability"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// Server implements the SecurityTokenService gRPC interface.
type Server struct {
	stsv1.UnimplementedSecurityTokenServiceServer
	sessionStore  SessionStore
	keyManager    KeyManager
	cookieManager CookieManager
	jwtIssuer     string
	jwtAudience   string
	jwtExpiry     int
	observability *observability.Observability
	server        *grpc.Server
}

var fallbackLogger = zap.NewNop()

// logger returns the zap logger from observability, or creates a new one if not available
func (s *Server) logger(ctx context.Context) *zap.Logger {
	if s.observability != nil && s.observability.Logger != nil {
		return s.observability.Logger.FromContext(ctx)
	}
	return fallbackLogger
}

// NewServer creates a new gRPC server.
func NewServer(store SessionStore, km KeyManager, cm CookieManager, issuer, audience string, expiry int, obs *observability.Observability) *Server {
	return &Server{
		sessionStore:  store,
		keyManager:    km,
		cookieManager: cm,
		jwtIssuer:     issuer,
		jwtAudience:   audience,
		jwtExpiry:     expiry,
		observability: obs,
	}
}

// ExchangeSession swaps an opaque session_id for an internal JWT.
func (s *Server) ExchangeSession(ctx context.Context, req *stsv1.ExchangeRequest) (*stsv1.ExchangeResponse, error) {
	if req.SessionCookie == "" {
		return nil, status.Error(codes.InvalidArgument, "session_cookie is required")
	}

	// Decode session cookie
	sessionID, err := s.cookieManager.Decode("session_id", req.SessionCookie)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session cookie")
	}

	// Get session from store
	sess, err := s.sessionStore.Get(ctx, sessionID)
	if err != nil {
		s.logger(ctx).Error("failed to get session", zap.Error(err))
		return nil, status.Error(codes.NotFound, "session not found")
	}

	// Merge session claims while ensuring primary identity is preserved
	claims := make(map[string]interface{})
	for k, v := range sess.Claims {
		claims[k] = v
	}
	if strings.Contains(sess.UserID, "@") {
		claims["email"] = sess.UserID
	} else if emailVal, ok := sess.Claims["email"].(string); ok && emailVal != "" {
		claims["email"] = emailVal
	} else {
		claims["email"] = sess.UserID
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
		s.logger(ctx).Error("failed to mint token", zap.Error(err))
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

	err := s.sessionStore.RevokeUserSessions(ctx, req.UserId)
	if err != nil {
		s.logger(ctx).Error("failed to revoke sessions",
			zap.String("user_id", req.UserId),
			zap.Error(err))

		return &stsv1.RevokeUserResponse{Success: false}, status.Error(codes.Internal, "failed to revoke sessions")
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

	s.logger(context.Background()).Info("gRPC server starting",
		zap.String("port", port),
		zap.Bool("reflection_enabled", true))
	return s.server.Serve(listener)
}

// StartWithInterceptors starts the gRPC server with observability interceptors
func (s *Server) StartWithInterceptors(port string) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	// Collect interceptors
	var unaryInterceptors []grpc.UnaryServerInterceptor

	if s.observability != nil {
		if s.observability.Logger != nil {
			unaryInterceptors = append(unaryInterceptors, observability.GRPCUnaryLoggingInterceptor(s.observability.Logger))
		}
		if s.observability.MetricsProvider != nil {
			unaryInterceptors = append(unaryInterceptors, observability.GRPCUnaryMetricsInterceptor(s.observability.MetricsProvider))
		}
		if s.observability.TracerProvider != nil {
			unaryInterceptors = append(unaryInterceptors, observability.GRPCUnaryTracingInterceptor(s.observability.TracerProvider.Tracer()))
		}
	}

	// Create gRPC server with interceptors
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
	}
	s.server = grpc.NewServer(opts...)

	// Register the SecurityTokenService
	stsv1.RegisterSecurityTokenServiceServer(s.server, s)

	// Register reflection service
	reflection.Register(s.server)

	s.logger(context.Background()).Info("gRPC server starting with interceptors",
		zap.String("port", port),
		zap.Bool("reflection_enabled", true),
		zap.Bool("observability_enabled", true))
	return s.server.Serve(listener)
}

// Stop gracefully stops the gRPC server.
func (s *Server) Stop() {
	if s.server != nil {
		s.server.GracefulStop()
	}
}
