package main

import (
	"fmt"
	"log"
	"time"

	"github.com/canonical/secure-token-service/internal/auth"
	"github.com/canonical/secure-token-service/internal/config"
	grpcserver "github.com/canonical/secure-token-service/internal/grpc"
	httpserver "github.com/canonical/secure-token-service/internal/http"
	"github.com/canonical/secure-token-service/internal/session"
	"github.com/spf13/cobra"
)

var (
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

	// Start HTTP server in goroutine
	httpSrv := httpserver.NewServer(sessionStore, keyManager)
	go func() {
		if err := httpSrv.Start(cfg.HTTPPort); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// Start gRPC server (blocks)
	grpcSrv := grpcserver.NewServer(sessionStore, keyManager, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTExpiry)
	if err := grpcSrv.Start(cfg.GRPCPort); err != nil {
		return fmt.Errorf("gRPC server failed: %w", err)
	}

	return nil
}
