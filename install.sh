#!/usr/bin/env bash
# End-to-end install: router sensor prep, Malcolm collector, capture container.
#
#   ./install.sh            everything
#   ./install.sh router     router preparation only
#   ./install.sh collector  Malcolm only
#   ./install.sh sensor     capture container only
#   ./install.sh mitm       TLS interception node (opt-in, see docs/MITM.md)
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

run_mitm() {
  printf '\n\033[1m==> Starting TLS interception node\033[0m\n'
  printf '    mode: %s  (proxy = nothing is redirected)\n' "${MITM_MODE:-proxy}"
  cd "${REPO_ROOT}/mitm"
  docker compose --env-file "${REPO_ROOT}/config.env" -f docker-compose.mitm.yml up -d --build
  cat <<EOF

    CA (install on each client you intend to intercept):
      ${REPO_ROOT}/mitm/ca/mitmproxy-ca-cert.pem
    Ship decrypted flows into OpenSearch:
      tools/mitm-ingest &
    Read docs/MITM.md before enabling transparent mode.
EOF
}

case "$STAGE" in
  router)    run_router ;;
  mitm)      run_mitm ;;
  collector) run_collector ;;
  sensor)    run_sensor ;;
  all)       run_router; run_collector; run_sensor ;;
  *) echo "usage: $0 [all|router|collector|sensor|mitm]" >&2; exit 1 ;;
esac
