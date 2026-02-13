// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/canonical/secure-token-service/internal/config"
	"github.com/canonical/secure-token-service/internal/session"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var (
	extendTTL    int
	extendDryRun bool
	extendID     string

	// extendSessionsCmd extends all sessions
	extendSessionsCmd = &cobra.Command{
		Use:   "extend-sessions",
		Short: "Extend all active sessions",
		Long: `Scan all active sessions, refresh tokens using the OIDC provider,
and extend the Valkey TTL for each session.

Requires OIDC_PROVIDER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and
OIDC_REDIRECT_URL environment variables to be set.`,
		RunE: runExtendSessions,
	}

	// extendSessionCmd extends a single session by ID
	extendSessionCmd = &cobra.Command{
		Use:   "extend-session",
		Short: "Extend a single session by ID",
		Long: `Refresh tokens for a specific session using the OIDC provider
and extend the Valkey TTL.

Requires OIDC_PROVIDER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and
OIDC_REDIRECT_URL environment variables to be set.`,
		RunE: runExtendSession,
	}
)

func init() {
	extendSessionsCmd.Flags().IntVar(&extendTTL, "ttl", 0, "Override session TTL in seconds (defaults to JWT_EXPIRY)")
	extendSessionsCmd.Flags().BoolVar(&extendDryRun, "dry-run", false, "Print what would be done without making changes")

	extendSessionCmd.Flags().IntVar(&extendTTL, "ttl", 0, "Override session TTL in seconds (defaults to JWT_EXPIRY)")
	extendSessionCmd.Flags().BoolVar(&extendDryRun, "dry-run", false, "Print what would be done without making changes")
	extendSessionCmd.Flags().StringVar(&extendID, "id", "", "Session ID to extend (required)")
	extendSessionCmd.MarkFlagRequired("id")

	rootCmd.AddCommand(extendSessionsCmd)
	rootCmd.AddCommand(extendSessionCmd)
}

// runExtendSessions extends all active sessions.
func runExtendSessions(cmd *cobra.Command, args []string) error {
	log.Println("Starting session extension for all sessions...")

	ctx := context.Background()

	store, oauth2Cfg, ttl, err := setupExtendDeps(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	sessions, err := store.ListAllExpiring(ctx)
	if err != nil {
		return fmt.Errorf("failed to list sessions: %w", err)
	}

	log.Printf("Found %d sessions", len(sessions))

	var refreshed, skipped, failed int

	for _, sess := range sessions {
		result, err := extendOneSession(ctx, store, oauth2Cfg, sess, ttl, extendDryRun)
		switch {
		case err != nil:
			failed++
			log.Printf("✗ Session %s (user: %s): %v", sess.SessionID, sess.UserID, err)
		case result == "skipped":
			skipped++
			log.Printf("- Session %s (user: %s): skipped (no refresh token)", sess.SessionID, sess.UserID)
		default:
			refreshed++
			log.Printf("✓ Session %s (user: %s): %s", sess.SessionID, sess.UserID, result)
		}
	}

	log.Println("--- Summary ---")
	log.Printf("Total: %d | Refreshed: %d | Skipped: %d | Failed: %d",
		len(sessions), refreshed, skipped, failed)

	return nil
}

// runExtendSession extends a single session by ID.
func runExtendSession(cmd *cobra.Command, args []string) error {
	log.Printf("Starting session extension for session: %s", extendID)

	ctx := context.Background()

	store, oauth2Cfg, ttl, err := setupExtendDeps(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	sess, err := store.Get(ctx, extendID)
	if err != nil {
		return fmt.Errorf("failed to get session %s: %w", extendID, err)
	}

	result, err := extendOneSession(ctx, store, oauth2Cfg, sess, ttl, extendDryRun)
	if err != nil {
		return fmt.Errorf("failed to extend session %s: %w", extendID, err)
	}

	if result == "skipped" {
		log.Printf("- Session %s: skipped (no refresh token)", extendID)
	} else {
		log.Printf("✓ Session %s: %s", extendID, result)
	}

	return nil
}

// setupExtendDeps initializes shared dependencies for extend commands.
func setupExtendDeps(ctx context.Context) (*session.ValkeyStore, *oauth2.Config, time.Duration, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Determine TTL
	ttl := time.Duration(cfg.SessionExpiry) * time.Second
	if extendTTL > 0 {
		ttl = time.Duration(extendTTL) * time.Second
	}
	log.Printf("Session TTL: %s", ttl)

	// Initialize Session Store
	store, err := session.NewValkeyStore(
		cfg.CacheAddr,
		cfg.CachePassword,
		cfg.CacheDB,
		time.Duration(cfg.SessionExpiry)*time.Second,
	)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to initialize session store: %w", err)
	}
	log.Println("Session store initialized")

	// Initialize OIDC provider
	provider, err := oidc.NewProvider(ctx, cfg.OIDCProviderURL)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	oauth2Cfg := &oauth2.Config{
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.OIDCScopes,
	}
	log.Println("OIDC provider initialized")

	return store, oauth2Cfg, ttl, nil
}

// extendOneSession refreshes tokens for a single session and updates the store.
// Returns a description string on success, "skipped" if no refresh token, or an error.
func extendOneSession(
	ctx context.Context,
	store session.Store,
	oauth2Cfg *oauth2.Config,
	sess *session.Session,
	ttl time.Duration,
	dryRun bool,
) (string, error) {
	if sess.RefreshToken == "" {
		return "skipped", nil
	}

	if dryRun {
		return fmt.Sprintf("would refresh (dry-run, ttl=%s)", ttl), nil
	}

	// Use oauth2.TokenSource to refresh the token
	tokenSource := oauth2Cfg.TokenSource(ctx, &oauth2.Token{
		RefreshToken: sess.RefreshToken,
	})

	newToken, err := tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("token refresh failed: %w", err)
	}

	// Update session with new tokens
	sess.AccessToken = newToken.AccessToken
	sess.ExpiresAt = newToken.Expiry

	if newToken.RefreshToken != "" {
		sess.RefreshToken = newToken.RefreshToken
	}

	// Extract new ID token if present
	if rawIDToken, ok := newToken.Extra("id_token").(string); ok && rawIDToken != "" {
		sess.IDToken = rawIDToken
	}

	// Persist with extended TTL
	if err := store.Set(ctx, sess, session.WithTTL(ttl)); err != nil {
		return "", fmt.Errorf("failed to persist session: %w", err)
	}

	return fmt.Sprintf("refreshed (ttl=%s, expires=%s)", ttl, sess.ExpiresAt.Format(time.RFC3339)), nil
}
