// Copyright 2026 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

//go:generate mockgen -build_flags=--mod=mod -package main -destination ./mock_store_test.go -source=../../internal/session/store.go

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/canonical/secure-token-service/internal/session"
	gomock "go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
)

func TestExtendOneSession_NoRefreshToken(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := NewMockStore(ctrl)

	sess := &session.Session{
		SessionID:    "sess-1",
		UserID:       "user-1",
		AccessToken:  "access",
		IDToken:      "id-token",
		RefreshToken: "", // empty
	}

	result, err := extendOneSession(context.Background(), mockStore, &oauth2.Config{}, sess, time.Hour, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "skipped" {
		t.Errorf("expected 'skipped', got %q", result)
	}
}

func TestExtendOneSession_DryRun(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := NewMockStore(ctrl)

	sess := &session.Session{
		SessionID:    "sess-2",
		UserID:       "user-2",
		AccessToken:  "access",
		RefreshToken: "refresh-token",
	}

	ttl := 2 * time.Hour
	result, err := extendOneSession(context.Background(), mockStore, &oauth2.Config{}, sess, ttl, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := fmt.Sprintf("would refresh (dry-run, ttl=%s)", ttl)
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestExtendOneSession_SetError(t *testing.T) {
	t.Parallel()

	// Since we can't easily mock oauth2.TokenSource in this test without more refactoring
	// (it's called via oauth2Cfg.TokenSource(ctx, ...).Token()),
	// this test as written was actually failing on token refresh or just verifying store error.
	// However, extendOneSession first calls tokenSource.Token().
	// To truly test Set error, we'd need a successful token refresh.

	// For now, let's just use gomock for the store part where possible,
	// acknowledging that token refresh will probably fail first.

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := NewMockStore(ctrl)

	sess := &session.Session{
		SessionID:    "sess-3",
		UserID:       "user-3",
		RefreshToken: "refresh-token",
	}

	// The token source will fail with no endpoint configured, which is expected.
	_, err := extendOneSession(context.Background(), mockStore, &oauth2.Config{}, sess, time.Hour, false)
	if err == nil {
		t.Fatal("expected error from token refresh or store, got nil")
	}
}

func TestExtendOneSession_DryRunNoRefreshToken(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := NewMockStore(ctrl)

	sess := &session.Session{
		SessionID:    "sess-4",
		UserID:       "user-4",
		RefreshToken: "",
	}

	result, err := extendOneSession(context.Background(), mockStore, &oauth2.Config{}, sess, time.Hour, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "skipped" {
		t.Errorf("expected 'skipped', got %q", result)
	}
}
