// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

// Package grpcserver provides the gRPC server implementation for the Secure Token Service.
package grpcserver

//go:generate mockgen -build_flags=--mod=mod -package grpcserver -destination ./mock_interfaces.go -source=./interfaces.go

import (
	"context"

	"github.com/canonical/secure-token-service/internal/session"
)

// CookieManager defines the interface for secure cookie operations
type CookieManager interface {
	Decode(name, value string) (string, error)
}

// SessionStore defines the interface for session storage operations
type SessionStore interface {
	Get(ctx context.Context, sessionID string) (*session.Session, error)
	RevokeUserSessions(ctx context.Context, userID string) error
}

// KeyManager defines the interface for JWT key management
type KeyManager interface {
	MintToken(subject, issuer, audience string, expirySeconds int, claims map[string]interface{}) (string, error)
}
