#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AASI_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

DATA_DIR="${DATA_DIR:-"${AASI_DIR}/data"}"
QDRANT_REST_URL="${QDRANT_REST_URL:-http://127.0.0.1:6333}"
QDRANT_COLLECTION="${QDRANT_COLLECTION:-agents_v1}"
COMPOSE_FILE="${COMPOSE_FILE:-"${AASI_DIR}/infra/docker-compose.yml"}"

DOCKER_DOWN=0
FORCE=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [--yes] [--docker-down] [--collection NAME]

Resets local experiment state:
  - deletes sled/merkle state under \$DATA_DIR (default: ${DATA_DIR})
  - optionally drops a Qdrant collection via REST (default: ${QDRANT_COLLECTION} at ${QDRANT_REST_URL})
  - optionally runs: docker compose -f <compose> down -v

Env overrides:
  DATA_DIR, QDRANT_REST_URL, QDRANT_COLLECTION, COMPOSE_FILE
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) FORCE=1; shift ;;
    --docker-down) DOCKER_DOWN=1; shift ;;
    --collection) QDRANT_COLLECTION="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

echo "Planned reset:"
echo "  DATA_DIR=${DATA_DIR}"
echo "  QDRANT_REST_URL=${QDRANT_REST_URL}"
echo "  QDRANT_COLLECTION=${QDRANT_COLLECTION}"
echo "  DOCKER_DOWN=${DOCKER_DOWN}"

if [[ "${FORCE}" -ne 1 ]]; then
  echo ""
  echo "Refusing to delete state without --yes"
  exit 1
fi

echo ""
echo "Deleting AASI local state under: ${DATA_DIR}"
rm -rf \
  "${DATA_DIR}/merkle_log" \
  "${DATA_DIR}/graph_db" \
  "${DATA_DIR}/stats_db" \
  "${DATA_DIR}/runs" \
  || true

if command -v curl >/dev/null 2>&1; then
  echo "Dropping Qdrant collection (if reachable): ${QDRANT_COLLECTION}"
  curl -sf -X DELETE "${QDRANT_REST_URL}/collections/${QDRANT_COLLECTION}" >/dev/null || true
else
  echo "curl not found; skipping Qdrant collection drop"
fi

if [[ "${DOCKER_DOWN}" -eq 1 ]]; then
  if command -v docker >/dev/null 2>&1; then
    echo "docker compose down -v: ${COMPOSE_FILE}"
    docker compose -f "${COMPOSE_FILE}" down -v
  else
    echo "docker not found; skipping --docker-down"
  fi
fi

echo "Reset complete."

