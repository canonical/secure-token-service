// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// JWKSKey represents a JSON Web Key stored in the database.
type JWKSKey struct {
	SID       string          // Set ID ("public", "public.retired")
	KID       string          // Key ID
	Version   int             // Key version
	KeyData   json.RawMessage // Complete JWK as JSONB
	CreatedAt time.Time
}

// JWKSRepository defines the interface for JWKS storage operations.
type JWKSRepository interface {
	// GetLatestActiveKey fetches the most recently created key from "public" set
	// This is used by mintToken to sign with the latest key
	GetLatestActiveKey(ctx context.Context) (*JWKSKey, error)

	// GetAllPublicKeys fetches all keys from both "public" and "public.retired" sets
	// This is used by JWKS endpoint to return all verification keys
	GetAllPublicKeys(ctx context.Context) ([]*JWKSKey, error)

	// GetKeyByKID fetches specific key by KID across all sets
	GetKeyByKID(ctx context.Context, kid string) (*JWKSKey, error)

	// SaveKey inserts new key to specified set
	SaveKey(ctx context.Context, key *JWKSKey) error

	// RotateKey moves current active key to retired set, inserts new active key (transaction)
	RotateKey(ctx context.Context, newKey *JWKSKey) error

	// DeleteKey removes key from database (for cleanup)
	DeleteKey(ctx context.Context, sid, kid string) error
}

// PostgresJWKSRepository implements JWKSRepository for PostgreSQL.
type PostgresJWKSRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresJWKSRepository creates a new PostgreSQL-backed JWKS repository.
func NewPostgresJWKSRepository(pool *pgxpool.Pool) *PostgresJWKSRepository {
	return &PostgresJWKSRepository{pool: pool}
}

// GetLatestActiveKey fetches the most recently created key from "public" set.
func (r *PostgresJWKSRepository) GetLatestActiveKey(ctx context.Context) (*JWKSKey, error) {
	query := `
		SELECT sid, kid, version, keydata, created_at
		FROM hydra_jwk
		WHERE sid = 'public'
		ORDER BY created_at DESC
		LIMIT 1
	`

	var key JWKSKey
	err := r.pool.QueryRow(ctx, query).Scan(
		&key.SID,
		&key.KID,
		&key.Version,
		&key.KeyData,
		&key.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("no active key found")
		}
		return nil, fmt.Errorf("failed to get latest active key: %w", err)
	}

	return &key, nil
}

// GetAllPublicKeys fetches all keys from both "public" and "public.retired" sets.
func (r *PostgresJWKSRepository) GetAllPublicKeys(ctx context.Context) ([]*JWKSKey, error) {
	query := `
		SELECT sid, kid, version, keydata, created_at
		FROM hydra_jwk
		WHERE sid IN ('public', 'public.retired')
		ORDER BY created_at DESC
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all public keys: %w", err)
	}
	defer rows.Close()

	var keys []*JWKSKey
	for rows.Next() {
		var key JWKSKey
		if err := rows.Scan(&key.SID, &key.KID, &key.Version, &key.KeyData, &key.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}
		keys = append(keys, &key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating keys: %w", err)
	}

	return keys, nil
}

// GetKeyByKID fetches specific key by KID across all sets.
func (r *PostgresJWKSRepository) GetKeyByKID(ctx context.Context, kid string) (*JWKSKey, error) {
	query := `
		SELECT sid, kid, version, keydata, created_at
		FROM hydra_jwk
		WHERE kid = $1
		LIMIT 1
	`

	var key JWKSKey
	err := r.pool.QueryRow(ctx, query, kid).Scan(
		&key.SID,
		&key.KID,
		&key.Version,
		&key.KeyData,
		&key.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("key not found: %s", kid)
		}
		return nil, fmt.Errorf("failed to get key by KID: %w", err)
	}

	return &key, nil
}

// SaveKey inserts new key to specified set.
func (r *PostgresJWKSRepository) SaveKey(ctx context.Context, key *JWKSKey) error {
	query := `
		INSERT INTO hydra_jwk (sid, kid, version, keydata, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.pool.Exec(ctx, query,
		key.SID,
		key.KID,
		key.Version,
		key.KeyData,
		key.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	return nil
}

// RotateKey moves current active key to retired set, inserts new active key (transaction).
func (r *PostgresJWKSRepository) RotateKey(ctx context.Context, newKey *JWKSKey) error {
	// Begin transaction
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Move current active key(s) to retired set
	updateQuery := `
		UPDATE hydra_jwk
		SET sid = 'public.retired'
		WHERE sid = 'public'
	`
	if _, err := tx.Exec(ctx, updateQuery); err != nil {
		return fmt.Errorf("failed to retire old  keys: %w", err)
	}

	// Insert new active key
	insertQuery := `
		INSERT INTO hydra_jwk (sid, kid, version, keydata, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	if _, err := tx.Exec(ctx, insertQuery,
		newKey.SID,
		newKey.KID,
		newKey.Version,
		newKey.KeyData,
		newKey.CreatedAt,
	); err != nil {
		return fmt.Errorf("failed to insert new key: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit rotation transaction: %w", err)
	}

	return nil
}

// DeleteKey removes key from database (for cleanup).
func (r *PostgresJWKSRepository) DeleteKey(ctx context.Context, sid, kid string) error {
	query := `
		DELETE FROM hydra_jwk
		WHERE sid = $1 AND kid = $2
	`

	result, err := r.pool.Exec(ctx, query, sid, kid)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("key not found: sid=%s, kid=%s", sid, kid)
	}

	return nil
}
