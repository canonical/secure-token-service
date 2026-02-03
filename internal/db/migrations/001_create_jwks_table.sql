-- Copyright 2025 Canonical Ltd
-- SPDX-License-Identifier: AGPL-3.0

-- Create JWKS table for storing JSON Web Keys
-- IDEMPOTENT: Safe to run multiple times
CREATE TABLE IF NOT EXISTS hydra_jwk (
    sid         VARCHAR(255) NOT NULL,
    kid         VARCHAR(255) NOT NULL,
    version     INTEGER NOT NULL DEFAULT 0,
    keydata     JSONB NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (sid, kid),
    CONSTRAINT hydra_jwk_sid_kid_key UNIQUE (sid, kid)
);

-- Index on sid for efficient set-based queries
-- IDEMPOTENT: Only creates if not exists
CREATE INDEX IF NOT EXISTS hydra_jwk_idx_id ON hydra_jwk (sid);

-- GIN index on keydata JSONB for efficient JSONB field queries
-- IDEMPOTENT: Only creates if not exists
CREATE INDEX IF NOT EXISTS hydra_jwk_kid_idx ON hydra_jwk USING GIN (keydata);
