// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/canonical/secure-token-service/internal/config"
	"github.com/canonical/secure-token-service/internal/db"
	"github.com/spf13/cobra"
)

var (
	// migrateCmd represents the migrate command
	migrateCmd = &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
		Long: `Run database migrations to create or update the database schema.
		
This command is idempotent and can be run multiple times safely.
It will create tables and indexes if they don't exist, and skip if they already exist.

Example:
  sts migrate                    # Run all pending migrations
  sts migrate --database-url=... # Use specific database URL`,
		RunE: runMigrate,
	}

	migrateDatabaseURL string
)

func init() {
	rootCmd.AddCommand(migrateCmd)

	// Allow overriding DATABASE_URL via flag
	migrateCmd.Flags().StringVar(&migrateDatabaseURL, "database-url", "", "PostgreSQL connection string (overrides DATABASE_URL env var)")
}

// runMigrate executes the database migration logic
func runMigrate(cmd *cobra.Command, args []string) error {
	log.Println("Running database migrations...")

	ctx := context.Background()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Use flag value if provided, otherwise use config
	databaseURL := migrateDatabaseURL
	if databaseURL == "" {
		databaseURL = cfg.DatabaseURL
	}

	log.Printf("Connecting to database: %s", databaseURL)

	// Initialize Database
	database, err := db.NewDB(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()
	log.Println("✓ Database connected")

	// Run migrations
	log.Println("Applying migrations...")
	if err := database.RunMigrations(ctx); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Println("✓ All migrations applied successfully")

	// Verify migration by checking table exists
	var tableExists bool
	query := `SELECT EXISTS (
		SELECT FROM information_schema.tables 
		WHERE table_name = 'hydra_jwk'
	)`

	if err := database.Pool().QueryRow(ctx, query).Scan(&tableExists); err != nil {
		log.Printf("Warning: Could not verify migration: %v", err)
	} else if tableExists {
		log.Println("✓ Verified: hydra_jwk table exists")

		// Show table stats
		var count int64
		countQuery := "SELECT COUNT(*) FROM hydra_jwk"
		if err := database.Pool().QueryRow(ctx, countQuery).Scan(&count); err == nil {
			log.Printf("✓ Current key count: %d", count)
		}
	}

	log.Println("Migration completed successfully!")
	return nil
}
