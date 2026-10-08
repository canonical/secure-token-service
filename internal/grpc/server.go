// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package grpcserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	stsv1 "github.com/canonical/secure-token-service/api/proto/v1"
	"github.com/canonical/secure-token-service/internal/auth"
	"github.com/canonical/secure-token-service/internal/observability"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// MaxTokenSizeBytes is the maximum permitted size in bytes for an incoming upstream token (64 KB).
const MaxTokenSizeBytes = 65536

// ServerOption configures a gRPC Server.
type ServerOption func(*Server)

// WithTokenVerifier sets the upstream token verifier for the server.
func WithTokenVerifier(verifier TokenVerifier) ServerOption {
	return func(s *Server) {
		s.tokenVerifier = verifier
	}
}

// Server implements the SecurityTokenService gRPC interface.
type Server struct {
	stsv1.UnimplementedSecurityTokenServiceServer
	sessionStore  SessionStore
	keyManager    KeyManager
	cookieManager CookieManager
	tokenVerifier TokenVerifier
	jwtIssuer     string
	jwtAudience   string
	jwtExpiry     int
	observability *observability.Observability
	server        *grpc.Server
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

// NewServer creates a new gRPC server.
func NewServer(store SessionStore, km KeyManager, cm CookieManager, issuer, audience string, expiry int, obs *observability.Observability, opts ...ServerOption) *Server {
	s := &Server{
		sessionStore:  store,
		keyManager:    km,
		cookieManager: cm,
		jwtIssuer:     issuer,
		jwtAudience:   audience,
		jwtExpiry:     expiry,
		observability: obs,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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
		s.logger(ctx).Error("failed to get session",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return nil, status.Error(codes.NotFound, "session not found")
	}

	// TODO: Add custom claims from session/user profile
	claims := map[string]interface{}{
		"email": sess.UserID,
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

// ExchangeToken swaps an upstream IdP access token (Ory Hydra OAuth2 Client Credentials) for an internal STS JWT.
func (s *Server) ExchangeToken(ctx context.Context, req *stsv1.ExchangeTokenRequest) (*stsv1.ExchangeResponse, error) {
	if req == nil || strings.TrimSpace(req.Token) == "" {
		s.auditLogExchange(ctx, "", "rejected", "token is required", codes.InvalidArgument, 0)
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	if len(req.Token) > MaxTokenSizeBytes {
		s.auditLogExchange(ctx, "", "rejected", "token exceeds maximum permitted size of 64 KB", codes.InvalidArgument, 0)
		return nil, status.Errorf(codes.InvalidArgument, "token exceeds maximum permitted size of %d bytes", MaxTokenSizeBytes)
	}

	if s.tokenVerifier == nil {
		s.auditLogExchange(ctx, "", "rejected", "token verifier not configured", codes.Unimplemented, 0)
		return nil, status.Error(codes.Unimplemented, "token verifier not configured")
	}

	vt, err := s.tokenVerifier.Verify(ctx, req.Token)
	if err != nil {
		if errors.Is(err, auth.ErrEmptyToken) {
			s.auditLogExchange(ctx, "", "rejected", "token is required", codes.InvalidArgument, 0)
			return nil, status.Error(codes.InvalidArgument, "token is required")
		}
		if errors.Is(err, auth.ErrTokenExpired) {
			s.auditLogExchange(ctx, "", "rejected", "token is expired", codes.Unauthenticated, 0)
			return nil, status.Error(codes.Unauthenticated, "token is expired")
		}
		if errors.Is(err, auth.ErrTokenExpiringSoon) {
			s.auditLogExchange(ctx, "", "rejected", "token expiring in less than 60 seconds", codes.Unauthenticated, 0)
			return nil, status.Error(codes.Unauthenticated, "token expiring in less than 60 seconds")
		}
		if errors.Is(err, auth.ErrMissingSubject) {
			s.auditLogExchange(ctx, "", "rejected", "token missing subject", codes.InvalidArgument, 0)
			return nil, status.Error(codes.InvalidArgument, "token missing subject")
		}
		if errors.Is(err, auth.ErrInvalidSubject) {
			s.auditLogExchange(ctx, "", "rejected", "token subject is invalid", codes.InvalidArgument, 0)
			return nil, status.Error(codes.InvalidArgument, "token subject is invalid")
		}
		if errors.Is(err, auth.ErrJWKSUnavailable) {
			s.auditLogExchange(ctx, "", "rejected", "upstream JWKS unavailable", codes.Unavailable, 0)
			s.logger(ctx).Error("upstream JWKS unavailable", zap.Error(err))
			return nil, status.Error(codes.Unavailable, "upstream JWKS unavailable")
		}
		s.auditLogExchange(ctx, "", "rejected", fmt.Sprintf("invalid token: %v", err), codes.Unauthenticated, 0)
		s.logger(ctx).Warn("token verification failed", zap.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}

	// Calculate remaining lifetime and enforce clamping
	remainingSeconds := int(time.Until(vt.ExpiresAt).Seconds())
	if remainingSeconds < 60 {
		s.auditLogExchange(ctx, vt.ClientID, "rejected", "token expiring in less than 60 seconds", codes.Unauthenticated, 0)
		return nil, status.Error(codes.Unauthenticated, "token expiring in less than 60 seconds")
	}

	clampedExpiry := s.jwtExpiry
	if remainingSeconds < clampedExpiry {
		clampedExpiry = remainingSeconds
	}

	// Map machine claims: preserve claims, set sub: client_id, and synthetic email: client_id@serviceaccount.local
	claims := make(map[string]interface{})
	for k, v := range vt.Claims {
		claims[k] = v
	}

	clientID := vt.ClientID
	if clientID == "" {
		clientID = vt.Subject
	}
	claims["sub"] = clientID
	claims["email"] = fmt.Sprintf("%s@serviceaccount.local", clientID)

	// Mint internal JWT
	token, err := s.keyManager.MintToken(
		clientID,
		s.jwtIssuer,
		s.jwtAudience,
		clampedExpiry,
		claims,
	)
	if err != nil {
		s.auditLogExchange(ctx, clientID, "rejected", "failed to mint token", codes.Internal, 0)
		s.logger(ctx).Error("failed to mint token", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to mint token")
	}

	if s.observability != nil && s.observability.MetricsProvider != nil {
		s.observability.MetricsProvider.RecordTokenMinted(ctx)
		s.observability.MetricsProvider.RecordM2MTokenClampedTTL(ctx, float64(clampedExpiry))
	}

	s.auditLogExchange(ctx, clientID, "success", "", codes.OK, clampedExpiry)

	return &stsv1.ExchangeResponse{
		AccessToken: token,
		ExpiresIn:   int64(clampedExpiry),
	}, nil
}

func (s *Server) auditLogExchange(ctx context.Context, clientID, outcome, reason string, code codes.Code, clampedTTL int) {
	fields := []zap.Field{
		zap.String("event", "sts.m2m.token_exchange"),
		zap.String("outcome", outcome),
		zap.String("grpc_code", code.String()),
	}
	if clientID != "" {
		fields = append(fields, zap.String("client_id", clientID))
	}
	if reason != "" {
		fields = append(fields, zap.String("reason", reason))
	}
	if clampedTTL > 0 {
		fields = append(fields, zap.Int("clamped_ttl_seconds", clampedTTL))
	}
	s.logger(ctx).Info("security audit: m2m token exchange", fields...)
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

// Stop gracefully stops the gRPC server and cleans up verifier resources.
func (s *Server) Stop() {
	if s.server != nil {
		s.server.GracefulStop()
	}
	if closer, ok := s.tokenVerifier.(io.Closer); ok && closer != nil {
		_ = closer.Close()
	}
}
