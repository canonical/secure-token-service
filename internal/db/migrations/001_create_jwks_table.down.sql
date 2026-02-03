-- Copyright 2025 Canonical Ltd
-- SPDX-License-Identifier: AGPL-3.0

-- Drop indexes first
DROP INDEX IF EXISTS hydra_jwk_kid_idx;
DROP INDEX IF EXISTS hydra_jwk_idx_id;

-- Drop table
DROP TABLE IF EXISTS hydra_jwk;
