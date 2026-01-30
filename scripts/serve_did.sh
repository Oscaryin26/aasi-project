#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AASI_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ROOT_DIR="${1:-"${AASI_DIR}/infra/did"}"
PORT="${2:-8000}"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"

if [[ ! -d "${ROOT_DIR}" ]]; then
  echo "DID doc root not found: ${ROOT_DIR}" >&2
  exit 1
fi

echo "Serving DID docs from: ${ROOT_DIR}"
echo "URL: http://${BIND_ADDR}:${PORT}/"

cd "${ROOT_DIR}"
python3 -m http.server "${PORT}" --bind "${BIND_ADDR}"

