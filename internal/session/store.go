// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
)

// ErrSessionNotFound is returned when a requested session is not found in the store.
var ErrSessionNotFound = errors.New("session not found")

// ErrInvalidSessionIdentity is returned when a stored session fails identity contract validation.
var ErrInvalidSessionIdentity = errors.New("invalid session identity")

// Session represents a user session with upstream tokens.
type Session struct {
	SessionID    string                 `json:"session_id"`
	UserID       string                 `json:"user_id"`
	AccessToken  string                 `json:"access_token"`  // Upstream Access Token (encrypted)
	IDToken      string                 `json:"id_token"`      // Upstream ID Token (encrypted)
	RefreshToken string                 `json:"refresh_token"` // Upstream Refresh Token (encrypted)
	ExpiresAt    time.Time              `json:"expires_at"`
	CreatedAt    time.Time              `json:"created_at"`
	Provider     string                 `json:"provider,omitempty"`
	Claims       map[string]interface{} `json:"claims,omitempty"`
}

func trimmedClaim(claims map[string]interface{}, key string) string {
	if claims == nil {
		return ""
	}
	val, ok := claims[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(val)
}

func isValidShortU1ID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if c <= 0x20 || c >= 0x7f || c == '/' || c == ':' {
			return false
		}
	}
	return true
}

// ValidateIdentity enforces the identity contract for stored sessions so
// ExchangeSession, /auth/me, /auth/sessions*, and extend-sessions fail closed
// uniformly on malformed, legacy, or inconsistent records.
func (s *Session) ValidateIdentity() error {
	if s == nil {
		return ErrInvalidSessionIdentity
	}
	userID := strings.TrimSpace(s.UserID)
	if userID == "" {
		return fmt.Errorf("%w: empty user_id", ErrInvalidSessionIdentity)
	}
	switch strings.ToLower(strings.TrimSpace(s.Provider)) {
	case "oidc":
		sub := trimmedClaim(s.Claims, "sub")
		if sub == "" || sub != userID {
			return fmt.Errorf("%w: oidc session missing matching sub claim", ErrInvalidSessionIdentity)
		}
		if trimmedClaim(s.Claims, "email") == "" {
			return fmt.Errorf("%w: oidc session missing email claim", ErrInvalidSessionIdentity)
		}
		if u1 := trimmedClaim(s.Claims, "u1_sso_id"); u1 != "" && !isValidShortU1ID(u1) {
			return fmt.Errorf("%w: oidc session has invalid u1_sso_id", ErrInvalidSessionIdentity)
		}
		return nil
	case "openid":
		u1 := trimmedClaim(s.Claims, "u1_sso_id")
		if u1 == "" || u1 != userID || !isValidShortU1ID(u1) {
			return fmt.Errorf("%w: openid session missing valid matching u1_sso_id", ErrInvalidSessionIdentity)
		}
		if trimmedClaim(s.Claims, "email") == "" {
			return fmt.Errorf("%w: openid session missing email claim", ErrInvalidSessionIdentity)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported provider %q", ErrInvalidSessionIdentity, s.Provider)
	}
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
	DeleteUserSession(ctx context.Context, userID, sessionID string) error
	RevokeUserSessions(ctx context.Context, userID string) error
	ListUserSessions(ctx context.Context, userID string) ([]*Session, error)
	RevokeUserSessionsExcept(ctx context.Context, userID, keepSessionID string) (int, error)
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
	if session == nil || strings.TrimSpace(session.UserID) == "" {
		return fmt.Errorf("failed to set session: user_id is required")
	}
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

	// Set expiration for the user sessions set key without shrinking an existing longer TTL.
	// Pipelining EXPIRE NX + EXPIRE GT avoids a two-round-trip TTL/EXPIRE TOCTOU race.
	if ttlSeconds > 0 {
		cmds := []valkey.Completed{
			s.client.B().Expire().Key(userSessionKey).Seconds(ttlSeconds).Nx().Build(),
			s.client.B().Expire().Key(userSessionKey).Seconds(ttlSeconds).Gt().Build(),
		}
		for _, resp := range s.client.DoMulti(ctx, cmds...) {
			if err := resp.Error(); err != nil {
				return fmt.Errorf("failed to set expiration on user sessions: %w", err)
			}
		}
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

// DeleteUserSession deletes a single session owned by userID without fetching or
// unmarshaling the target session payload. It verifies ownership via the user's
// session index, deletes the session key, and removes the ID from the index.
// Returns ErrSessionNotFound when the session does not exist, has already expired,
// or belongs to another user.
func (s *ValkeyStore) DeleteUserSession(ctx context.Context, userID, sessionID string) error {
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("failed to check session ownership: user_id is required")
	}
	userSessionKey := fmt.Sprintf("user_sessions:%s", userID)

	isMember, err := s.client.Do(ctx, s.client.B().Sismember().Key(userSessionKey).Member(sessionID).Build()).AsBool()
	if err != nil {
		return fmt.Errorf("failed to check session ownership: %w", err)
	}
	if !isMember {
		return ErrSessionNotFound
	}

	key := fmt.Sprintf("session:%s", sessionID)
	deleted, err := s.client.Do(ctx, s.client.B().Del().Key(key).Build()).AsInt64()
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	if err := s.client.Do(ctx, s.client.B().Srem().Key(userSessionKey).Member(sessionID).Build()).Error(); err != nil {
		return fmt.Errorf("failed to remove from user sessions: %w", err)
	}

	if deleted == 0 {
		return ErrSessionNotFound
	}

	return nil
}

// RevokeUserSessions removes all sessions for a given user.
func (s *ValkeyStore) RevokeUserSessions(ctx context.Context, userID string) error {
	_, err := s.RevokeUserSessionsExcept(ctx, userID, "")
	return err
}

// ListUserSessions returns all active sessions for a user with ExpiresAt derived
// from each session's active Valkey TTL, lazily pruning expired IDs from the user set.
func (s *ValkeyStore) ListUserSessions(ctx context.Context, userID string) ([]*Session, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("failed to list user sessions: user_id is required")
	}
	userSessionKey := fmt.Sprintf("user_sessions:%s", userID)

	sessionIDs, err := s.client.Do(ctx, s.client.B().Smembers().Key(userSessionKey).Build()).AsStrSlice()
	if err != nil {
		return nil, fmt.Errorf("failed to list user sessions: %w", err)
	}

	sessions := make([]*Session, 0, len(sessionIDs))
	var staleIDs []string

	for _, sessionID := range sessionIDs {
		key := fmt.Sprintf("session:%s", sessionID)

		data, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).AsBytes()
		if err != nil {
			if valkey.IsValkeyNil(err) {
				staleIDs = append(staleIDs, sessionID)
				continue
			}
			return nil, fmt.Errorf("failed to get session %s: %w", sessionID, err)
		}

		ttlSeconds, err := s.client.Do(ctx, s.client.B().Ttl().Key(key).Build()).AsInt64()
		if err != nil {
			return nil, fmt.Errorf("failed to get ttl for session %s: %w", sessionID, err)
		}
		if ttlSeconds == -2 {
			staleIDs = append(staleIDs, sessionID)
			continue
		}

		var sess Session
		if err := json.Unmarshal(data, &sess); err != nil {
			continue
		}
		if sess.SessionID == "" {
			sess.SessionID = sessionID
		}
		if ttlSeconds > 0 {
			sess.ExpiresAt = time.Now().UTC().Add(time.Duration(ttlSeconds) * time.Second)
		}

		sessions = append(sessions, &sess)
	}

	// Lazily prune expired/missing session IDs from user_sessions:<userID>.
	if len(staleIDs) > 0 {
		_ = s.client.Do(ctx, s.client.B().Srem().Key(userSessionKey).Member(staleIDs...).Build()).Error()
	}

	sort.Slice(sessions, func(i, j int) bool {
		if !sessions[i].CreatedAt.Equal(sessions[j].CreatedAt) {
			return sessions[i].CreatedAt.After(sessions[j].CreatedAt)
		}
		return sessions[i].SessionID < sessions[j].SessionID
	})

	return sessions, nil
}

// RevokeUserSessionsExcept deletes all sessions belonging to userID except keepSessionID
// and returns the number of active sessions revoked. Revoked IDs are removed from
// user_sessions:<userID> via SREM so concurrent SADD calls are preserved (Valkey
// auto-deletes the set when its last member is removed).
func (s *ValkeyStore) RevokeUserSessionsExcept(ctx context.Context, userID, keepSessionID string) (int, error) {
	if strings.TrimSpace(userID) == "" {
		return 0, fmt.Errorf("failed to get user sessions: user_id is required")
	}
	userSessionKey := fmt.Sprintf("user_sessions:%s", userID)

	sessionIDs, err := s.client.Do(ctx, s.client.B().Smembers().Key(userSessionKey).Build()).AsStrSlice()
	if err != nil {
		return 0, fmt.Errorf("failed to get user sessions: %w", err)
	}

	var toRemove []string
	var errs []error
	revokedCount := 0

	for _, sessionID := range sessionIDs {
		if keepSessionID != "" && sessionID == keepSessionID {
			continue
		}

		key := fmt.Sprintf("session:%s", sessionID)
		deleted, err := s.client.Do(ctx, s.client.B().Del().Key(key).Build()).AsInt64()
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to delete session %s: %w", sessionID, err))
			continue
		}
		toRemove = append(toRemove, sessionID)
		revokedCount += int(deleted)
	}

	// Always SREM deleted IDs rather than DEL user_sessions:<userID> so a concurrent
	// Set (SADD after SMEMBERS) is never wiped; Valkey auto-deletes empty sets.
	if len(toRemove) > 0 {
		if err := s.client.Do(ctx, s.client.B().Srem().Key(userSessionKey).Member(toRemove...).Build()).Error(); err != nil {
			errs = append(errs, fmt.Errorf("failed to remove revoked sessions from index: %w", err))
		}
	}

	if len(errs) > 0 {
		return revokedCount, errors.Join(errs...)
	}

	return revokedCount, nil
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
