#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_PATH="${PROJECT_ROOT}/bin/sts"

# Load demo environment variables
# shellcheck source=demo/env.sh
source "${SCRIPT_DIR}/env.sh"

if [[ ! -x "${BIN_PATH}" ]]; then
    echo "Binary ${BIN_PATH} not found. Run ./demo/prepare-demo.sh first." >&2
    exit 1
fi

cd "${PROJECT_ROOT}"
exec "${BIN_PATH}" serve "$@"
