// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/canonical/secure-token-service/internal/auth"
	"github.com/canonical/secure-token-service/internal/config"
	"github.com/canonical/secure-token-service/internal/cookie"
	grpcserver "github.com/canonical/secure-token-service/internal/grpc"
	httpserver "github.com/canonical/secure-token-service/internal/http"
	"github.com/canonical/secure-token-service/internal/session"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var (
	// serveCmd represents the serve command
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the Secure Token service",
		Long:  `Start the Secure Token service with both HTTP and gRPC servers`,
		RunE:  runServe,
	}
)

func init() {
	rootCmd.AddCommand(serveCmd)
}

// runServe executes the serve command logic
func runServe(cmd *cobra.Command, args []string) error {
	log.Println("Starting Session Service (Janus)...")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	log.Printf("Configuration loaded: HTTP=%s, gRPC=%s", cfg.HTTPPort, cfg.GRPCPort)

	// Initialize Key Manager
	keyManager, err := auth.NewKeyManager(cfg.PrivateKeyPath, cfg.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}
	log.Println("Key manager initialized")

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
	log.Println("Session store initialized")

	// Initialize Cookie Manager
	cookieManager := cookie.NewCookieManager(
		[]byte(cfg.CookieHashKey),
		[]byte(cfg.CookieBlockKey),
	)
	log.Println("Cookie manager initialized")

	// Initialize OIDC
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, cfg.OIDCProviderURL)
	if err != nil {
		return fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.OIDCScopes,
	}
	log.Println("OIDC provider initialized")

	// Start HTTP server in goroutine
	oidcProvider := httpserver.NewOIDCProvider(provider, oauth2Config)
	httpSrv := httpserver.NewServer(sessionStore, keyManager, cookieManager, oidcProvider)
	go func() {
		if err := httpSrv.Start(cfg.HTTPPort); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server failed: %v", err)
		}
	}()

	// Start gRPC server in goroutine
	grpcSrv := grpcserver.NewServer(sessionStore, keyManager, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTExpiry)
	go func() {
		if err := grpcSrv.Start(cfg.GRPCPort); err != nil {
			log.Printf("gRPC server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("Received signal: %v, shutting down...", sig)

	// Shutdown HTTP Server with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("HTTP server forced to shutdown: %v", err)
	}

	// Stop gRPC Server
	grpcSrv.Stop()

	log.Println("Server exiting")
	return nil
}
