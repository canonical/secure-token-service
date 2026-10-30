#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_PATH="${PROJECT_ROOT}/bin/sts"

# Load demo environment variables
# shellcheck source=demo/env.sh
source "${SCRIPT_DIR}/env.sh"

PG_CONTAINER="${PG_CONTAINER:-authz-postgres}"
PG_HOST="${PG_HOST:-localhost}"
PG_PORT="${PG_PORT:-5433}"
PG_USER="${PG_USER:-authorization-service}"
PG_DB="${PG_DB:-sts}"

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}   $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()   { echo -e "${RED}[ERR]${NC}  $*" >&2; }

cd "${PROJECT_ROOT}"

# 1. Build ./bin/sts if missing or requested via --build
if [[ ! -x "${BIN_PATH}" ]] || [[ "${1:-}" == "--build" ]]; then
    log_info "Building ${BIN_PATH}..."
    make build GO_BIN=sts
    log_ok "Binary ready at ${BIN_PATH}"
else
    log_ok "Using existing binary at ${BIN_PATH} (pass --build to recompile)"
fi

# 2. Ensure Valkey is running (used by sts for session & JWKS caching on localhost:6379)
if ! docker ps --format '{{.Names}}' | grep -qE '^(secure-token-valkey|authz-valkey)$'; then
    log_info "Starting Valkey container on localhost:6379..."
    docker compose -f "${PROJECT_ROOT}/docker-compose.yml" up -d valkey
    log_ok "Valkey started"
else
    log_ok "Valkey is already running"
fi

# 3. Wait for PostgreSQL to be ready and ensure 'sts' database exists
check_pg_ready() {
    if docker ps --format '{{.Names}}' | grep -qx "${PG_CONTAINER}"; then
        docker exec "${PG_CONTAINER}" pg_isready -U "${PG_USER}" -d "${PG_DB}" >/dev/null 2>&1
    elif command -v pg_isready >/dev/null 2>&1; then
        pg_isready -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" >/dev/null 2>&1
    else
        (echo >/dev/tcp/"${PG_HOST}"/"${PG_PORT}") >/dev/null 2>&1
    fi
}

log_info "Waiting for PostgreSQL on ${PG_HOST}:${PG_PORT} (db: ${PG_DB})..."
for i in {1..30}; do
    if check_pg_ready; then
        break
    fi
    sleep 1
    if [[ $i -eq 30 ]]; then
        log_err "Timeout waiting for PostgreSQL on ${PG_HOST}:${PG_PORT}"
        exit 1
    fi
done

# Ensure the 'sts' database exists if running via the shared authz-postgres container
if docker ps --format '{{.Names}}' | grep -qx "${PG_CONTAINER}"; then
    if ! docker exec -e PGPASSWORD=password "${PG_CONTAINER}" psql -U "${PG_USER}" -d "${PG_DB}" -c "SELECT 1;" >/dev/null 2>&1; then
        log_warn "Database '${PG_DB}' not found in ${PG_CONTAINER}. Creating it..."
        docker exec -e PGPASSWORD=password "${PG_CONTAINER}" psql -U "${PG_USER}" -d postgres -c "CREATE DATABASE ${PG_DB};" >/dev/null
    fi
fi
log_ok "PostgreSQL is ready"

# 4. Run database migrations (`sts migrate`)
log_info "Applying PostgreSQL migrations (sts migrate)..."
"${BIN_PATH}" migrate
log_ok "Database migrations applied"

echo ""
log_ok "Demo prerequisites are ready!"
echo ""
echo "Start the application with:"
echo "  ./demo/run-app.sh"
