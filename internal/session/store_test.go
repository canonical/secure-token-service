// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/valkey"
	valkeygo "github.com/valkey-io/valkey-go"
)

// sanitizeName converts test names to valid container names
// Container names must match: [a-zA-Z0-9][a-zA-Z0-9_.-]*
func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ToLower(name)
	return name
}

func setupTestValkey(t *testing.T) (*ValkeyStore, *valkey.ValkeyContainer) {
	ctx := context.Background()

	// Start Valkey container with unique name based on test name
	containerName := fmt.Sprintf("sts-session-%s", sanitizeName(t.Name()))
	valkeyContainer, err := valkey.Run(ctx, "valkey/valkey:7.2-alpine",
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name: containerName,
			},
		}),
	)
	if err != nil {
		t.Fatalf("Failed to start Valkey container: %v", err)
	}

	// Get the host and port
	host, err := valkeyContainer.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get container host: %v", err)
	}

	port, err := valkeyContainer.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatalf("Failed to get container port: %v", err)
	}

	// Create valkey client with host:port format
	valkeyClient, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress: []string{host + ":" + port.Port()},
	})
	if err != nil {
		t.Fatalf("Failed to create valkey client: %v", err)
	}

	store := &ValkeyStore{
		client: valkeyClient,
		ttl:    1 * time.Hour,
	}

	return store, valkeyContainer
}

func TestValkeyStore_SetAndGet(t *testing.T) {
	t.Parallel()
	store, container := setupTestValkey(t)
	defer func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()

	session := &Session{
		SessionID:    "sess123",
		UserID:       "user456",
		AccessToken:  "access_token_encrypted",
		IDToken:      "id_token_encrypted",
		RefreshToken: "refresh_token_encrypted",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
		Provider:     "openid",
		Claims: map[string]interface{}{
			"email":    "alice@canonical.com",
			"nickname": "alice",
		},
	}

	// Test Set
	err := store.Set(ctx, session)
	if err != nil {
		t.Fatalf("Failed to set session: %v", err)
	}

	// Test Get
	retrieved, err := store.Get(ctx, "sess123")
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	if retrieved.SessionID != session.SessionID {
		t.Errorf("SessionID mismatch: got %v, want %v", retrieved.SessionID, session.SessionID)
	}

	if retrieved.UserID != session.UserID {
		t.Errorf("UserID mismatch: got %v, want %v", retrieved.UserID, session.UserID)
	}

	if retrieved.AccessToken != session.AccessToken {
		t.Errorf("AccessToken mismatch: got %v, want %v", retrieved.AccessToken, session.AccessToken)
	}

	if retrieved.Provider != session.Provider {
		t.Errorf("Provider mismatch: got %v, want %v", retrieved.Provider, session.Provider)
	}

	if retrieved.Claims["email"] != "alice@canonical.com" {
		t.Errorf("Claims[email] mismatch: got %v, want alice@canonical.com", retrieved.Claims["email"])
	}

	if retrieved.Claims["nickname"] != "alice" {
		t.Errorf("Claims[nickname] mismatch: got %v, want alice", retrieved.Claims["nickname"])
	}
}

func TestSession_JSONSerialization(t *testing.T) {
	orig := &Session{
		SessionID: "sess-json",
		UserID:    "alice@canonical.com",
		Provider:  "openid",
		Claims: map[string]interface{}{
			"email":    "alice@canonical.com",
			"nickname": "alice",
			"name":     "Alice Smith",
		},
		ExpiresAt: time.Now().Truncate(time.Second),
		CreatedAt: time.Now().Truncate(time.Second),
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var parsed Session
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if parsed.SessionID != orig.SessionID {
		t.Errorf("SessionID mismatch: got %v, want %v", parsed.SessionID, orig.SessionID)
	}
	if parsed.UserID != orig.UserID {
		t.Errorf("UserID mismatch: got %v, want %v", parsed.UserID, orig.UserID)
	}
	if parsed.Provider != orig.Provider {
		t.Errorf("Provider mismatch: got %v, want %v", parsed.Provider, orig.Provider)
	}
	if parsed.Claims["email"] != "alice@canonical.com" {
		t.Errorf("Claims[email] mismatch: got %v, want alice@canonical.com", parsed.Claims["email"])
	}
	if parsed.Claims["name"] != "Alice Smith" {
		t.Errorf("Claims[name] mismatch: got %v, want Alice Smith", parsed.Claims["name"])
	}
}

func TestValkeyStore_GetNonExistent(t *testing.T) {
	t.Parallel()
	store, container := setupTestValkey(t)
	defer func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	if err == nil {
		t.Error("Expected error when getting nonexistent session")
	}
}

func TestValkeyStore_Delete(t *testing.T) {
	t.Parallel()
	store, container := setupTestValkey(t)
	defer func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()

	session := &Session{
		SessionID:    "sess_to_delete",
		UserID:       "user789",
		AccessToken:  "token",
		IDToken:      "id",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}

	// Set session
	err := store.Set(ctx, session)
	if err != nil {
		t.Fatalf("Failed to set session: %v", err)
	}

	// Delete session
	err = store.Delete(ctx, "sess_to_delete")
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	// Verify deletion
	_, err = store.Get(ctx, "sess_to_delete")
	if err == nil {
		t.Error("Session should not exist after deletion")
	}
}

func TestValkeyStore_RevokeUserSessions(t *testing.T) {
	t.Parallel()
	store, container := setupTestValkey(t)
	defer func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()

	// Create multiple sessions for the same user
	sessions := []*Session{
		{
			SessionID:    "sess1",
			UserID:       "user_multi",
			AccessToken:  "token1",
			IDToken:      "id1",
			RefreshToken: "refresh1",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			CreatedAt:    time.Now(),
		},
		{
			SessionID:    "sess2",
			UserID:       "user_multi",
			AccessToken:  "token2",
			IDToken:      "id2",
			RefreshToken: "refresh2",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			CreatedAt:    time.Now(),
		},
		{
			SessionID:    "sess3",
			UserID:       "user_multi",
			AccessToken:  "token3",
			IDToken:      "id3",
			RefreshToken: "refresh3",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			CreatedAt:    time.Now(),
		},
	}

	for _, sess := range sessions {
		err := store.Set(ctx, sess)
		if err != nil {
			t.Fatalf("Failed to set session %s: %v", sess.SessionID, err)
		}
	}

	// Revoke all sessions for user
	err := store.RevokeUserSessions(ctx, "user_multi")
	if err != nil {
		t.Fatalf("Failed to revoke user sessions: %v", err)
	}

	// Verify all sessions are deleted
	for _, sess := range sessions {
		_, err := store.Get(ctx, sess.SessionID)
		if err == nil {
			t.Errorf("Session %s should be deleted", sess.SessionID)
		}
	}
}

func TestValkeyStore_UserSessionTracking(t *testing.T) {
	t.Parallel()
	store, container := setupTestValkey(t)
	defer func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()

	session := &Session{
		SessionID:    "sess_track",
		UserID:       "user_track",
		AccessToken:  "token",
		IDToken:      "id",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}

	err := store.Set(ctx, session)
	if err != nil {
		t.Fatalf("Failed to set session: %v", err)
	}

	// Verify user session tracking
	members, err := store.client.Do(ctx, store.client.B().Smembers().Key("user_sessions:user_track").Build()).AsStrSlice()
	if err != nil {
		t.Fatalf("Failed to get user sessions: %v", err)
	}

	if len(members) != 1 || members[0] != "sess_track" {
		t.Errorf("User session tracking incorrect: got %v", members)
	}
}

func TestNewValkeyStore_WithUsername(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	containerName := fmt.Sprintf("sts-session-%s", sanitizeName(t.Name()))
	valkeyContainer, err := valkey.Run(ctx, "valkey/valkey:7.2-alpine",
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name: containerName,
			},
		}),
	)
	if err != nil {
		t.Fatalf("Failed to start Valkey container: %v", err)
	}
	defer func() {
		if err := valkeyContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	host, err := valkeyContainer.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get container host: %v", err)
	}
	port, err := valkeyContainer.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatalf("Failed to get container port: %v", err)
	}
	addr := host + ":" + port.Port()

	store, err := NewValkeyStore(addr, "default", "", 0, time.Hour)
	if err != nil {
		t.Fatalf("NewValkeyStore with username failed: %v", err)
	}
	defer store.Close()

	// Verify the store is functional by writing and reading a session.
	sess := &Session{
		SessionID:    "sess-user",
		UserID:       "user-user",
		AccessToken:  "token",
		IDToken:      "id",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
		CreatedAt:    time.Now(),
	}
	if err := store.Set(ctx, sess); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	got, err := store.Get(ctx, sess.SessionID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.SessionID != sess.SessionID {
		t.Errorf("SessionID mismatch: got %v, want %v", got.SessionID, sess.SessionID)
	}
}

func TestNewValkeyClient_WithUsername(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	containerName := fmt.Sprintf("sts-session-%s", sanitizeName(t.Name()))
	valkeyContainer, err := valkey.Run(ctx, "valkey/valkey:7.2-alpine",
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name: containerName,
			},
		}),
	)
	if err != nil {
		t.Fatalf("Failed to start Valkey container: %v", err)
	}
	defer func() {
		if err := valkeyContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	host, err := valkeyContainer.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get container host: %v", err)
	}
	port, err := valkeyContainer.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatalf("Failed to get container port: %v", err)
	}
	addr := host + ":" + port.Port()

	client, err := NewValkeyClient(addr, "default", "", 0)
	if err != nil {
		t.Fatalf("NewValkeyClient with username failed: %v", err)
	}
	defer client.Close()

	// Verify the client is functional with a simple PING.
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		t.Fatalf("PING failed: %v", err)
	}
}

func TestValkeyStore_ListUserSessions_AndRevokeExcept_AndTTL(t *testing.T) {
	t.Parallel()
	store, container := setupTestValkey(t)
	defer func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	ctx := context.Background()
	userID := "user-crud@canonical.com"
	now := time.Now().UTC().Truncate(time.Second)

	// Set a long-TTL session first, then a shorter-TTL session; user_sessions TTL must not shrink.
	if err := store.Set(ctx, &Session{
		SessionID: "sess-long",
		UserID:    userID,
		Provider:  "oidc",
		CreatedAt: now.Add(-5 * time.Minute),
		ExpiresAt: now.Add(time.Minute), // stale stored timestamp
	}, WithTTL(2*time.Hour)); err != nil {
		t.Fatalf("Set(sess-long) failed: %v", err)
	}
	if err := store.Set(ctx, &Session{
		SessionID: "sess-short",
		UserID:    userID,
		Provider:  "openid",
		CreatedAt: now.Add(-1 * time.Minute),
		ExpiresAt: now.Add(time.Minute),
	}, WithTTL(10*time.Minute)); err != nil {
		t.Fatalf("Set(sess-short) failed: %v", err)
	}

	userSetTTL, err := store.client.Do(ctx, store.client.B().Ttl().Key("user_sessions:"+userID).Build()).AsInt64()
	if err != nil {
		t.Fatalf("TTL(user_sessions) failed: %v", err)
	}
	if userSetTTL < 3600 {
		t.Fatalf("user_sessions TTL shrank below 3600s: got %d", userSetTTL)
	}

	// Inject a stale/expired session ID directly into user_sessions:<userID>.
	if err := store.client.Do(ctx, store.client.B().Sadd().Key("user_sessions:"+userID).Member("sess-expired").Build()).Error(); err != nil {
		t.Fatalf("SADD stale member failed: %v", err)
	}

	// ListUserSessions should return both active sessions with TTL-derived ExpiresAt and prune sess-expired.
	before := time.Now()
	listed, err := store.ListUserSessions(ctx, userID)
	if err != nil {
		t.Fatalf("ListUserSessions failed: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(listed))
	}
	if listed[0].SessionID != "sess-short" || listed[1].SessionID != "sess-long" {
		t.Fatalf("unexpected order: got [%s, %s]", listed[0].SessionID, listed[1].SessionID)
	}
	if delta := listed[1].ExpiresAt.Sub(before); delta < 7000*time.Second {
		t.Errorf("expected sess-long ExpiresAt derived from ~2h Valkey TTL, got delta=%v", delta)
	}

	members, err := store.client.Do(ctx, store.client.B().Smembers().Key("user_sessions:"+userID).Build()).AsStrSlice()
	if err != nil {
		t.Fatalf("SMEMBERS failed: %v", err)
	}
	for _, m := range members {
		if m == "sess-expired" {
			t.Fatal("expected sess-expired to be lazily pruned by ListUserSessions")
		}
	}

	// Revoke all except sess-long.
	revoked, err := store.RevokeUserSessionsExcept(ctx, userID, "sess-long")
	if err != nil {
		t.Fatalf("RevokeUserSessionsExcept failed: %v", err)
	}
	if revoked != 1 {
		t.Fatalf("expected revoked=1, got %d", revoked)
	}
	if _, err := store.Get(ctx, "sess-long"); err != nil {
		t.Errorf("expected sess-long to remain active, got %v", err)
	}
	if _, err := store.Get(ctx, "sess-short"); err == nil {
		t.Error("expected sess-short to be deleted")
	}

	// Revoke all remaining.
	revokedAll, err := store.RevokeUserSessionsExcept(ctx, userID, "")
	if err != nil {
		t.Fatalf("RevokeUserSessionsExcept(all) failed: %v", err)
	}
	if revokedAll != 1 {
		t.Fatalf("expected revokedAll=1, got %d", revokedAll)
	}
	if _, err := store.Get(ctx, "sess-long"); err == nil {
		t.Error("expected sess-long to be deleted")
	}
}
