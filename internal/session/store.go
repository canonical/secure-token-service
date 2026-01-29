// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeycompat"
)

// Session represents a user session with upstream tokens.
type Session struct {
	SessionID    string    `json:"session_id"`
	UserID       string    `json:"user_id"`
	AccessToken  string    `json:"access_token"`  // Upstream Access Token (encrypted)
	IDToken      string    `json:"id_token"`      // Upstream ID Token (encrypted)
	RefreshToken string    `json:"refresh_token"` // Upstream Refresh Token (encrypted)
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// Store defines the interface for session storage.
type Store interface {
	Get(ctx context.Context, sessionID string) (*Session, error)
	Set(ctx context.Context, session *Session) error
	Delete(ctx context.Context, sessionID string) error
	RevokeUserSessions(ctx context.Context, userID string) error
}

// ValkeyStore implements Store using Valkey.
type ValkeyStore struct {
	client       valkeycompat.Cmdable
	valkeyClient valkey.Client // Underlying valkey client for Close
	ttl          time.Duration
}

// NewValkeyStore creates a new Valkey-based session store.
func NewValkeyStore(addr, password string, db int, ttl time.Duration) (*ValkeyStore, error) {
	opt := valkey.ClientOption{
		InitAddress: []string{addr},
	}
	if password != "" {
		opt.Password = password
	}
	if db != 0 {
		opt.SelectDB = db
	}

	valkeyClient, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("failed to create valkey client: %w", err)
	}

	client := valkeycompat.NewAdapter(valkeyClient)

	return &ValkeyStore{
		client:       client,
		valkeyClient: valkeyClient,
		ttl:          ttl,
	}, nil
}

// Get retrieves a session by ID from Valkey.
func (s *ValkeyStore) Get(ctx context.Context, sessionID string) (*Session, error) {
	key := fmt.Sprintf("session:%s", sessionID)

	data, err := s.client.Get(ctx, key).Result()
	if err != nil {
		// Check for nil reply (different error messages in different compat versions)
		if err.Error() == "redis: nil" || err.Error() == "valkey: nil reply" {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var session Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &session, nil
}

// Set stores a session in Valkey.
func (s *ValkeyStore) Set(ctx context.Context, session *Session) error {
	key := fmt.Sprintf("session:%s", session.SessionID)
	userSessionKey := fmt.Sprintf("user_sessions:%s", session.UserID)

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	// Store session
	if err := s.client.Set(ctx, key, data, s.ttl).Err(); err != nil {
		return fmt.Errorf("failed to set session: %w", err)
	}

	// Track user's sessions
	if err := s.client.SAdd(ctx, userSessionKey, session.SessionID).Err(); err != nil {
		return fmt.Errorf("failed to track user session: %w", err)
	}

	return nil
}

// Delete removes a session from Valkey.
func (s *ValkeyStore) Delete(ctx context.Context, sessionID string) error {
	// Get session to find user ID
	session, err := s.Get(ctx, sessionID)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("session:%s", sessionID)
	userSessionKey := fmt.Sprintf("user_sessions:%s", session.UserID)

	// Delete session
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Remove from user's session set
	if err := s.client.SRem(ctx, userSessionKey, sessionID).Err(); err != nil {
		return fmt.Errorf("failed to remove from user sessions: %w", err)
	}

	return nil
}

// RevokeUserSessions removes all sessions for a given user.
func (s *ValkeyStore) RevokeUserSessions(ctx context.Context, userID string) error {
	userSessionKey := fmt.Sprintf("user_sessions:%s", userID)

	// Get all session IDs for this user
	sessionIDs, err := s.client.SMembers(ctx, userSessionKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Delete each session
	for _, sessionID := range sessionIDs {
		key := fmt.Sprintf("session:%s", sessionID)
		if err := s.client.Del(ctx, key).Err(); err != nil {
			// Log error but continue
			continue
		}
	}

	// Delete the user sessions set
	if err := s.client.Del(ctx, userSessionKey).Err(); err != nil {
		return fmt.Errorf("failed to delete user sessions set: %w", err)
	}

	return nil
}

// Close closes the Valkey connection.
func (s *ValkeyStore) Close() error {
	s.valkeyClient.Close()
	return nil
}
