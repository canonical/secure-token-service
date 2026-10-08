// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"
)

// ErrSessionNotFound is returned when a requested session is not found in the store.
var ErrSessionNotFound = errors.New("session not found")

// Session represents a user session with upstream tokens.
type Session struct {
	SessionID    string    `json:"session_id"`
	UserID       string    `json:"user_id"`
	AccessToken  string    `json:"access_token"`  // Upstream Access Token (encrypted)
	IDToken      string    `json:"id_token"`      // Upstream ID Token (encrypted)
	RefreshToken string    `json:"refresh_token"` // Upstream Refresh Token (encrypted)
	ExpiresAt    time.Time              `json:"expires_at"`
	CreatedAt    time.Time              `json:"created_at"`
	Provider     string                 `json:"provider,omitempty"`
	Claims       map[string]interface{} `json:"claims,omitempty"`
}

// SetOptions holds optional configuration for Store.Set.
type SetOptions struct {
	TTL *time.Duration // nil = use default store TTL
}

// SetOption is a functional option for Store.Set.
type SetOption func(*SetOptions)

// WithTTL overrides the default TTL for a Set operation.
func WithTTL(ttl time.Duration) SetOption {
	return func(o *SetOptions) {
		o.TTL = &ttl
	}
}

// Store defines the interface for session storage.
type Store interface {
	Get(ctx context.Context, sessionID string) (*Session, error)
	Set(ctx context.Context, session *Session, opts ...SetOption) error
	Delete(ctx context.Context, sessionID string) error
	RevokeUserSessions(ctx context.Context, userID string) error
	ListAllExpiring(ctx context.Context) ([]*Session, error)
}

// ValkeyStore implements Store using Valkey.
type ValkeyStore struct {
	client valkey.Client
	ttl    time.Duration
}

// NewValkeyStore creates a new Valkey-based session store.
func NewValkeyStore(addr, username, password string, db int, ttl time.Duration) (*ValkeyStore, error) {
	opt := valkey.ClientOption{
		InitAddress: []string{addr},
	}
	if username != "" {
		opt.Username = username
	}
	if password != "" {
		opt.Password = password
	}
	if db != 0 {
		opt.SelectDB = db
	}

	client, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("failed to create valkey client: %w", err)
	}

	return &ValkeyStore{
		client: client,
		ttl:    ttl,
	}, nil
}

// Get retrieves a session by ID from Valkey.
func (s *ValkeyStore) Get(ctx context.Context, sessionID string) (*Session, error) {
	key := fmt.Sprintf("session:%s", sessionID)

	data, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).AsBytes()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &session, nil
}

// Set stores a session in Valkey.
func (s *ValkeyStore) Set(ctx context.Context, session *Session, opts ...SetOption) error {
	options := SetOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	ttl := s.ttl
	if options.TTL != nil {
		ttl = *options.TTL
	}
	ttlSeconds := int64(ttl.Seconds())

	key := fmt.Sprintf("session:%s", session.SessionID)
	userSessionKey := fmt.Sprintf("user_sessions:%s", session.UserID)

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	// Store session
	if err := s.client.Do(ctx, s.client.B().Setex().Key(key).Seconds(ttlSeconds).Value(string(data)).Build()).Error(); err != nil {
		return fmt.Errorf("failed to set session: %w", err)
	}

	// Track user's sessions
	if err := s.client.Do(ctx, s.client.B().Sadd().Key(userSessionKey).Member(session.SessionID).Build()).Error(); err != nil {
		return fmt.Errorf("failed to track user session: %w", err)
	}

	// Set expiration for the user sessions set key
	if err := s.client.Do(ctx, s.client.B().Expire().Key(userSessionKey).Seconds(ttlSeconds).Build()).Error(); err != nil {
		return fmt.Errorf("failed to set expiration on user sessions: %w", err)
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
	if err := s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Remove from user's session set
	if err := s.client.Do(ctx, s.client.B().Srem().Key(userSessionKey).Member(sessionID).Build()).Error(); err != nil {
		return fmt.Errorf("failed to remove from user sessions: %w", err)
	}

	return nil
}

// RevokeUserSessions removes all sessions for a given user.
func (s *ValkeyStore) RevokeUserSessions(ctx context.Context, userID string) error {
	userSessionKey := fmt.Sprintf("user_sessions:%s", userID)

	// Get all session IDs for this user
	sessionIDs, err := s.client.Do(ctx, s.client.B().Smembers().Key(userSessionKey).Build()).AsStrSlice()
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Delete each session
	for _, sessionID := range sessionIDs {
		key := fmt.Sprintf("session:%s", sessionID)
		if err := s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error(); err != nil {
			// Log error but continue
			continue
		}
	}

	// Delete the user sessions set
	if err := s.client.Do(ctx, s.client.B().Del().Key(userSessionKey).Build()).Error(); err != nil {
		return fmt.Errorf("failed to delete user sessions set: %w", err)
	}

	return nil
}

// expiryThreshold is the TTL threshold below which sessions are considered expiring.
const expiryThreshold = 2 * time.Hour

// ListAllExpiring returns sessions with less than 2h TTL remaining.
func (s *ValkeyStore) ListAllExpiring(ctx context.Context) ([]*Session, error) {
	var sessions []*Session
	var cursor uint64 = 0

	for {
		scanRes, err := s.client.Do(ctx, s.client.B().Scan().Cursor(cursor).Match("session:*").Count(100).Build()).AsScanEntry()
		if err != nil {
			return nil, fmt.Errorf("failed to scan sessions: %w", err)
		}

		nextCursor, keys := scanRes.Cursor, scanRes.Elements

		for _, key := range keys {
			// Check remaining TTL
			// valkey-go TTL command returns seconds
			ttl, err := s.client.Do(ctx, s.client.B().Ttl().Key(key).Build()).AsInt64()
			if err != nil || ttl <= 0 {
				continue
			}

			// Compare seconds
			if time.Duration(ttl)*time.Second > expiryThreshold {
				continue
			}

			data, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).AsBytes()
			if err != nil {
				// Session may have expired between scan and get or error
				continue
			}

			var sess Session
			if err := json.Unmarshal(data, &sess); err != nil {
				continue
			}

			sessions = append(sessions, &sess)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return sessions, nil
}

// Close closes the Valkey connection.
func (s *ValkeyStore) Close() error {
	s.client.Close()
	return nil
}

// NewValkeyClient creates a new Valkey client for caching purposes.
func NewValkeyClient(addr, username, password string, db int) (valkey.Client, error) {
	opt := valkey.ClientOption{
		InitAddress: []string{addr},
	}
	if username != "" {
		opt.Username = username
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

	return valkeyClient, nil
}
