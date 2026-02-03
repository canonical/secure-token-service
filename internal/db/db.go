// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"context"
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps a PostgreSQL connection pool.
type DB struct {
	pool *pgxpool.Pool
}

// NewDB creates a new database connection pool.
func NewDB(ctx context.Context, databaseURL string) (*DB, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Ping to verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{pool: pool}, nil
}

// Close closes the database connection pool.
func (db *DB) Close() {
	db.pool.Close()
}

// RunMigrations executes the SQL migrations.
func (db *DB) RunMigrations(ctx context.Context) error {
	// Read the up migration file
	migrationSQL, err := migrationsFS.ReadFile("migrations/001_create_jwks_table.sql")
	if err != nil {
		return fmt.Errorf("failed to read migration file: %w", err)
	}

	// Execute migration
	if _, err := db.pool.Exec(ctx, string(migrationSQL)); err != nil {
		return fmt.Errorf("failed to execute migration: %w", err)
	}

	return nil
}

// Pool returns the underlying connection pool for use by repositories.
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}
