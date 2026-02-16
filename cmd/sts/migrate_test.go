// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/canonical/secure-token-service/internal/db"
	"github.com/spf13/cobra"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// sanitizeName converts test names to valid container names
func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ToLower(name)
	return name
}

func setupTestPostgres(t *testing.T) (string, *postgres.PostgresContainer) {
	ctx := context.Background()

	containerName := fmt.Sprintf("sts-migrate-test-%s", sanitizeName(t.Name()))
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name: containerName,
			},
		}),
	)
	if err != nil {
		t.Fatalf("Failed to start PostgreSQL container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("Failed to get connection string: %v", err)
	}

	// Retry connection until PostgreSQL is ready
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		dbConn, err := db.NewDB(ctx, connStr)
		if err == nil {
			dbConn.Close()
			break
		}
		if i < maxRetries-1 {
			time.Sleep(time.Second)
		}
	}

	return connStr, pgContainer
}

func TestMigrateUp(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	connStr, container := setupTestPostgres(t)
	defer func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	// Set required environment variables
	requiredVars := map[string]string{
		"OIDC_PROVIDER_URL":  "https://example.com",
		"OIDC_CLIENT_ID":     "test-client",
		"OIDC_CLIENT_SECRET": "test-secret",
		"OIDC_REDIRECT_URL":  "http://localhost:8080/callback",
		"DATABASE_URL":       connStr,
	}

	for k, v := range requiredVars {
		old := os.Getenv(k)
		os.Setenv(k, v)
		defer os.Setenv(k, old)
	}

	// Set the global flag variable (override)
	migrateDatabaseURL = connStr

	// Run migration up
	cmd := &cobra.Command{}
	err := runMigrate(cmd, []string{"up"})
	if err != nil {
		t.Fatalf("runMigrate checking up failed: %v", err)
	}

	// Verify table exists
	ctx := context.Background()
	database, err := db.NewDB(ctx, connStr)
	if err != nil {
		t.Fatalf("Failed to connect to database for verification: %v", err)
	}
	defer database.Close()

	var tableExists bool
	query := `SELECT EXISTS (
		SELECT FROM information_schema.tables 
		WHERE table_name = 'hydra_jwk'
	)`

	if err := database.Pool().QueryRow(ctx, query).Scan(&tableExists); err != nil {
		t.Fatalf("Failed to query table existence: %v", err)
	}

	if !tableExists {
		t.Error("Expected hydra_jwk table to exist, but it does not")
	}
}

func TestMigrateDown(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	connStr, container := setupTestPostgres(t)
	defer func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	// Set required environment variables
	requiredVars := map[string]string{
		"OIDC_PROVIDER_URL":  "https://example.com",
		"OIDC_CLIENT_ID":     "test-client",
		"OIDC_CLIENT_SECRET": "test-secret",
		"OIDC_REDIRECT_URL":  "http://localhost:8080/callback",
		"DATABASE_URL":       connStr,
	}

	for k, v := range requiredVars {
		old := os.Getenv(k)
		os.Setenv(k, v)
		defer os.Setenv(k, old)
	}

	// Set the global flag variable (override)
	migrateDatabaseURL = connStr

	// Run migration up first
	cmd := &cobra.Command{}
	if err := runMigrate(cmd, []string{"up"}); err != nil {
		t.Fatalf("runMigrate up failed: %v", err)
	}

	// Run migration down
	if err := runMigrate(cmd, []string{"down"}); err != nil {
		t.Fatalf("runMigrate down failed: %v", err)
	}

	// Verify table does NOT exist
	ctx := context.Background()
	database, err := db.NewDB(ctx, connStr)
	if err != nil {
		t.Fatalf("Failed to connect to database for verification: %v", err)
	}
	defer database.Close()

	var tableExists bool
	query := `SELECT EXISTS (
		SELECT FROM information_schema.tables 
		WHERE table_name = 'hydra_jwk'
	)`

	if err := database.Pool().QueryRow(ctx, query).Scan(&tableExists); err != nil {
		t.Fatalf("Failed to query table existence: %v", err)
	}

	if tableExists {
		t.Error("Expected hydra_jwk table to NOT exist, but it does")
	}
}

func TestCustomValidArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		args      []string
		wantError bool
	}{
		{
			name:      "Empty args",
			args:      []string{},
			wantError: false,
		},
		{
			name:      "Valid up",
			args:      []string{"up"},
			wantError: false,
		},
		{
			name:      "Valid down without version",
			args:      []string{"down"},
			wantError: false,
		},
		{
			name:      "Valid down with version 0",
			args:      []string{"down", "0"},
			wantError: false,
		},
		{
			name:      "Valid down with version 5",
			args:      []string{"down", "5"},
			wantError: false,
		},
		{
			name:      "Valid check",
			args:      []string{"check"},
			wantError: false,
		},
		{
			name:      "Invalid command",
			args:      []string{"invalid"},
			wantError: true,
		},
		{
			name:      "Invalid second arg with up",
			args:      []string{"up", "extra"},
			wantError: true,
		},
		{
			name:      "Invalid second arg with check",
			args:      []string{"check", "extra"},
			wantError: true,
		},
		{
			name:      "Invalid non-down command with 2 args",
			args:      []string{"up", "1"},
			wantError: true,
		},
		{
			name:      "Down with non-numeric second arg",
			args:      []string{"down", "abc"},
			wantError: true,
		},
		{
			name:      "Too many args",
			args:      []string{"down", "1", "extra"},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			err := customValidArgs()(cmd, tt.args)
			if (err != nil) != tt.wantError {
				t.Errorf("customValidArgs() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}
