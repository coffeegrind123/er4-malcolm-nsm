#!/usr/bin/env bash
# End-to-end install: router sensor prep, Malcolm collector, capture container.
#
#   ./install.sh            everything
#   ./install.sh router     router preparation only
#   ./install.sh collector  Malcolm only
#   ./install.sh sensor     capture container only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="${1:-all}"

if [[ ! -f "${REPO_ROOT}/config.env" ]]; then
  echo "config.env not found. Start from the template:" >&2
  echo "  cp config.env.example config.env && \$EDITOR config.env" >&2
  exit 1
fi
# shellcheck disable=SC1091
source "${REPO_ROOT}/config.env"

run_router()    { bash "${REPO_ROOT}/router/prepare-router.sh"; }
run_collector() { bash "${REPO_ROOT}/collector/install-malcolm.sh"; }

run_sensor() {
  printf '\n\033[1m==> Starting capture sensor\033[0m\n'
  cd "${REPO_ROOT}/sensor"
  docker compose --env-file "${REPO_ROOT}/config.env" -f docker-compose.sensor.yml up -d --build
  sleep 3
  docker logs er4-sensor 2>&1 | tail -5
  cat <<EOF

    Captures rotate every ${ROTATE_SECS}s into ${DATA_ROOT}/pcap/upload.
    Follow with: docker logs -f er4-sensor
EOF
}

case "$STAGE" in
  router)    run_router ;;
  collector) run_collector ;;
  sensor)    run_sensor ;;
  all)       run_router; run_collector; run_sensor ;;
  *) echo "usage: $0 [all|router|collector|sensor]" >&2; exit 1 ;;
esac
