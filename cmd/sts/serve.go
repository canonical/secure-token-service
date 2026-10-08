// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/canonical/secure-token-service/internal/auth"
	"github.com/canonical/secure-token-service/internal/auth/openid"
	"github.com/canonical/secure-token-service/internal/config"
	"github.com/canonical/secure-token-service/internal/cookie"
	"github.com/canonical/secure-token-service/internal/db"
	grpcserver "github.com/canonical/secure-token-service/internal/grpc"
	httpserver "github.com/canonical/secure-token-service/internal/http"
	"github.com/canonical/secure-token-service/internal/observability"
	"github.com/canonical/secure-token-service/internal/session"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
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
	// Create a temporary logger for early startup messages
	tempLogger, _ := observability.NewLogger("info", false)
	tempLogger.Info("starting Session Service (Janus)")

	ctx := context.Background()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	tempLogger.Info("configuration loaded",
		zap.String("http_port", cfg.HTTPPort),
		zap.String("grpc_port", cfg.GRPCPort),
		zap.String("database", cfg.DatabaseURL))

	// Initialize Database
	database, err := db.NewDB(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()
	tempLogger.Info("database connected")

	// NOTE: Migrations are NOT run automatically on startup
	// Run migrations manually with: ./bin/sts migrate

	// Initialize JWKS Repository
	jwksRepo := db.NewPostgresJWKSRepository(database.Pool())
	tempLogger.Info("JWKS repository initialized")

	// Initialize Observability
	obs, err := observability.Initialize(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize observability: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := obs.Shutdown(shutdownCtx); err != nil {
			obs.Logger.Error("failed to shutdown observability", zap.Error(err))
		}
	}()
	obs.Logger.Info("observability initialized",
		zap.Bool("logging", true),
		zap.Bool("metrics", cfg.MetricsEnabled),
		zap.Bool("tracing", cfg.TracingEnabled))

	// Initialize Valkey client for caching
	valkeyClient, err := session.NewValkeyClient(cfg.CacheAddr, cfg.CacheUsername, cfg.CachePassword, cfg.CacheDB)
	if err != nil {
		return fmt.Errorf("failed to initialize valkey client: %w", err)
	}
	obs.Logger.Info("valkey client initialized for caching")

	// Initialize Key Manager with caching
	cacheTTL := time.Duration(cfg.JWKSCacheTTL) * time.Second
	keyManager, err := auth.NewKeyManager(ctx, jwksRepo, valkeyClient, cacheTTL)
	if err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}
	obs.Logger.Info("key manager initialized",
		zap.Int("cache_ttl_seconds", cfg.JWKSCacheTTL))

	// Initialize Session Store
	sessionStore, err := session.NewValkeyStore(
		cfg.CacheAddr,
		cfg.CacheUsername,
		cfg.CachePassword,
		cfg.CacheDB,
		time.Duration(cfg.SessionExpiry)*time.Second,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize session store: %w", err)
	}
	obs.Logger.Info("session store initialized")

	// Initialize Cookie Manager
	cookieManager, err := cookie.NewCookieManager(
		[]byte(cfg.CookieHashKey),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize cookie manager: %w", err)
	}
	obs.Logger.Info("cookie manager initialized")

	// Initialize OIDC
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
	obs.Logger.Info("OIDC provider initialized")

	// Build allowed hosts for return_to redirection
	allowedHosts := append([]string{}, cfg.AllowedReturnToHosts...)
	if redirectURL, err := url.Parse(cfg.OIDCRedirectURL); err == nil && redirectURL.Host != "" {
		allowedHosts = append(allowedHosts, redirectURL.Host)
	}

	// Initialize Ubuntu One OpenID client
	openIDClient := openid.NewClient(cfg.UbuntuOneOpenIDURL, cfg.UbuntuOneRealm, nil)
	obs.Logger.Info("Ubuntu One OpenID provider initialized",
		zap.String("url", cfg.UbuntuOneOpenIDURL),
		zap.String("realm", cfg.UbuntuOneRealm),
		zap.String("default_provider", cfg.DefaultAuthProvider))

	// Start HTTP server in goroutine with observability
	oidcProvider := httpserver.NewOIDCProvider(provider, oauth2Config)
	httpSrvWithObs := httpserver.NewServer(
		sessionStore,
		keyManager,
		cookieManager,
		oidcProvider,
		obs,
		httpserver.WithAllowedHosts(allowedHosts),
		httpserver.WithOpenIDProvider(openIDClient),
		httpserver.WithDefaultAuthProvider(cfg.DefaultAuthProvider),
		httpserver.WithSessionExpiry(time.Duration(cfg.SessionExpiry)*time.Second),
	)
	go func() {
		if err := httpSrvWithObs.StartWithMiddleware(cfg.HTTPPort); err != nil && err != http.ErrServerClosed {
			obs.Logger.Error("HTTP server failed", zap.Error(err))
		}
	}()

	// Start gRPC server in goroutine with observability
	grpcSrvWithObs := grpcserver.NewServer(sessionStore, keyManager, cookieManager, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTExpiry, obs)
	go func() {
		if err := grpcSrvWithObs.StartWithInterceptors(cfg.GRPCPort); err != nil {
			obs.Logger.Error("gRPC server failed", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	obs.Logger.Info("received shutdown signal", zap.String("signal", sig.String()))

	// Shutdown HTTP Server with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if httpSrvWithObs != nil {
		if err := httpSrvWithObs.Shutdown(shutdownCtx); err != nil {
			obs.Logger.Error("HTTP server forced to shutdown", zap.Error(err))
		}
	}

	// Stop gRPC Server
	if grpcSrvWithObs != nil {
		grpcSrvWithObs.Stop()
	}

	obs.Logger.Info("server exiting")
	return nil
}
