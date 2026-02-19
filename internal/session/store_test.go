// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"context"
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
