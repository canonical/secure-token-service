package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/canonical/secure-token-service/internal/config"
	"github.com/canonical/secure-token-service/internal/cookie"
	"github.com/canonical/secure-token-service/internal/session"
	"github.com/spf13/cobra"
)

var (
	createCookieCmd = &cobra.Command{
		Use:   "create-cookie",
		Short: "Create a test session and encrypted cookie",
		Long:  `Creates a new session in the store and generates a valid encrypted cookie value for testing.`,
		RunE:  runCreateCookie,
	}

	// Flags
	userID       string
	accessToken  string
	idToken      string
	refreshToken string
	sessionID    string
	expiry       int
)

func init() {
	createCookieCmd.Flags().StringVar(&userID, "user-id", "test-user-123", "User ID for the session")
	createCookieCmd.Flags().StringVar(&accessToken, "access-token", "test-access-token", "Access Token")
	createCookieCmd.Flags().StringVar(&idToken, "id-token", "test-id-token", "ID Token")
	createCookieCmd.Flags().StringVar(&refreshToken, "refresh-token", "test-refresh-token", "Refresh Token")
	createCookieCmd.Flags().StringVar(&sessionID, "session-id", "", "Session ID (optional, auto-generated if empty)")
	createCookieCmd.Flags().IntVar(&expiry, "expiry", 3600, "Session expiry in seconds")

	rootCmd.AddCommand(createCookieCmd)
}

func runCreateCookie(cmd *cobra.Command, args []string) error {
	// Load config
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize Session Store
	sessionStore, err := session.NewValkeyStore(
		cfg.CacheAddr,
		cfg.CachePassword,
		cfg.CacheDB,
		time.Duration(cfg.JWTExpiry)*time.Second,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize session store: %w", err)
	}
	defer sessionStore.Close()

	// Initialize Cookie Manager
	cookieManager := cookie.NewCookieManager(
		[]byte(cfg.CookieHashKey),
		[]byte(cfg.CookieBlockKey),
	)

	// Generate Session ID if not provided
	if sessionID == "" {
		sessionID = uuid.New().String()
	}

	// Create Session
	now := time.Now()
	sess := &session.Session{
		SessionID:    sessionID,
		UserID:       userID,
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		ExpiresAt:    now.Add(time.Duration(expiry) * time.Second),
		CreatedAt:    now,
	}

	ctx := context.Background()
	if err := sessionStore.Set(ctx, sess); err != nil {
		return fmt.Errorf("failed to store session: %w", err)
	}

	log.Printf("Session created: %s", sessionID)

	// Encrypt Cookie
	cookieValue, err := cookieManager.Encode("session_id", sessionID)
	if err != nil {
		return fmt.Errorf("failed to encode cookie: %w", err)
	}

	fmt.Println("\n--- Test Data ---")
	fmt.Printf("Session ID: %s\n", sessionID)
	fmt.Printf("User ID:    %s\n", userID)
	fmt.Printf("Cookie:     %s\n", cookieValue)
	fmt.Println("-----------------")

	return nil
}
