// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"strconv"

	"github.com/canonical/secure-token-service/internal/config"
	"github.com/canonical/secure-token-service/internal/db"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/spf13/cobra"
)

var (
	// migrateCmd represents the migrate command
	migrateCmd = &cobra.Command{
		Use:   "migrate [command]",
		Short: "Run database migrations",
		Long: `Run database migrations to create or update the database schema.

Commands:
  up      Apply all pending migrations
  down    Rollback the last migration
  check   Verify if migrations are pending

If no command is provided, 'up' is run by default.`,
		Args:      customValidArgs(),
		RunE:      runMigrate,
		ValidArgs: []string{"up", "down", "check"},
	}

	migrateDatabaseURL string
)

func customValidArgs() func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}

		if err := cobra.RangeArgs(0, 2)(cmd, args); err != nil {
			return err
		}

		first := args[0]
		switch first {
		case "up", "check":
			if len(args) > 1 {
				return fmt.Errorf("command %q does not accept arguments", first)
			}
		case "down":
			if len(args) == 2 {
				if _, err := strconv.ParseInt(args[1], 10, 64); err != nil {
					return fmt.Errorf("invalid version number: %q", args[1])
				}
			}
		default:
			return fmt.Errorf("invalid command: %q", first)
		}

		return nil
	}
}

func init() {
	rootCmd.AddCommand(migrateCmd)

	// Allow overriding DATABASE_URL via flag
	migrateCmd.Flags().StringVar(&migrateDatabaseURL, "database-url", "", "PostgreSQL connection string (overrides DATABASE_URL env var)")
}

// runMigrate executes the database migration logic
func runMigrate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	command := "up"
	if len(args) > 0 {
		command = args[0]
	}

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

	log.Printf("Connecting to database...")

	// Initialize Database using internal/db to leverage its connection logic (ping, etc)
	// primarily to create the pool, then we get stdlib DB from it.
	database, err := db.NewDB(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()
	log.Println("✓ Database connected")

	// Get stdlib DB specific for Goose
	stdDB := stdlib.OpenDB(*database.Pool().Config().ConnConfig)
	defer stdDB.Close()

	// Use fs.Sub to get the migrations directory as root
	migrationsFS, err := fs.Sub(db.MigrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("failed to substring migrations FS: %w", err)
	}

	// Setup Goose Provider
	provider, err := goose.NewProvider(goose.DialectPostgres, stdDB, migrationsFS)
	if err != nil {
		return fmt.Errorf("failed to create goose provider: %w", err)
	}

	log.Printf("Running command: %s", command)

	switch command {
	case "up":
		if _, err := provider.Up(ctx); err != nil {
			return fmt.Errorf("failed to migrate up: %w", err)
		}
		log.Println("✓ Migrations up completed")
	case "down":
		// Down rolls back a single migration by default in many tools,
		// but let's check what user asked: "down for downgrading step by step (or all in)"
		// Goose Down rolls back the most recent migration.
		if len(args) > 1 {
			// Version provided
			version, err := strconv.ParseInt(args[1], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid version: %w", err)
			}
			if _, err := provider.DownTo(ctx, version); err != nil {
				return fmt.Errorf("failed to migrate down to version %d: %w", version, err)
			}
			log.Printf("✓ Migration down to version %d completed", version)
		} else {
			if _, err := provider.Down(ctx); err != nil {
				return fmt.Errorf("failed to migrate down: %w", err)
			}
			log.Println("✓ Migration down completed")
		}
	case "check":
		// Check version and pending
		dbVersion, err := provider.GetDBVersion(ctx)
		if err != nil {
			return fmt.Errorf("failed to get db version: %w", err)
		}
		log.Printf("Current DB Version: %d", dbVersion)

		hasPending, err := provider.HasPending(ctx)
		if err != nil {
			return fmt.Errorf("failed to check pending migrations: %w", err)
		}

		if hasPending {
			log.Println("! There are pending migrations.")
			// Optionally list them? Status() would do that.
			sources, err := provider.Status(ctx)
			if err == nil {
				for _, s := range sources {
					if s.State == goose.StatePending {
						log.Printf("  Pending: %s", s.Source.Path)
					}
				}
			}
			return fmt.Errorf("pending migrations exist")
		} else {
			log.Println("✓ Database is up to date.")
		}
	default:
		return fmt.Errorf("unknown command: %s", command)
	}

	return nil
}
