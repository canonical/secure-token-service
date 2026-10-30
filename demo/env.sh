#!/usr/bin/env bash
# Shared environment variables for the Secure Token Service (sts) local demo

export CACHE_ADDR="${CACHE_ADDR:-localhost:6379}"
export CACHE_DB="${CACHE_DB:-0}"
export CACHE_PASSWORD="${CACHE_PASSWORD:-}"
export COOKIE_BLOCK_KEY="${COOKIE_BLOCK_KEY:-01234567890123456789012345678901}"
export COOKIE_HASH_KEY="${COOKIE_HASH_KEY:-0123456789012345678901234567890123456789012345678901234567890123}"
export DATABASE_URL="${DATABASE_URL:-postgres://authorization-service:password@localhost:5433/sts?sslmode=disable}"
export GRPC_PORT="${GRPC_PORT:-9090}"
export HTTP_PORT="${HTTP_PORT:-8080}"
export JWT_AUDIENCE="${JWT_AUDIENCE:-internal-services}"
export JWT_EXPIRY="${JWT_EXPIRY:-3600}"
export JWT_ISSUER="${JWT_ISSUER:-session-service}"
export OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-1062245546180-psaeq8g5qn3og4h87qg9qqpf11dce0ta.apps.googleusercontent.com}"
export OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET:-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}"
export OIDC_PROVIDER_URL="${OIDC_PROVIDER_URL:-https://accounts.google.com}"
export OIDC_REDIRECT_URL="${OIDC_REDIRECT_URL:-http://localhost:8080/auth/callback}"
export OIDC_SCOPES="${OIDC_SCOPES:-openid,https://www.googleapis.com/auth/userinfo.profile,https://www.googleapis.com/auth/userinfo.email}"
