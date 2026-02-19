// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"context"
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var MigrationsFS embed.FS

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

// RunMigrations executes the SQL migrations using goose.
func (db *DB) RunMigrations(ctx context.Context) error {
	goose.SetBaseFS(MigrationsFS)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set dialect: %w", err)
	}

	// Convert pgx pool config to stdlib db for goose
	stdDB := stdlib.OpenDB(*db.pool.Config().ConnConfig)
	defer stdDB.Close()

	if err := goose.Up(stdDB, "migrations"); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

// Pool returns the underlying connection pool for use by repositories.
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}
