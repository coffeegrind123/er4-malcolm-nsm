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

# Everything that makes the deployment survivable and legible, rather than merely
# running. Each of these was written after the corresponding failure happened, so
# none of it is optional in practice - and every one is idempotent, so a re-run
# is always safe.
run_ops() {
  printf '\n\033[1m==> Operational tooling\033[0m\n'

  # Snapshots FIRST. An out-of-memory host makes OpenSearch report a corrupt
  # index, and a corrupt index cannot be repaired - only restored. Setting this
  # up after the first incident is too late by definition.
  "${REPO_ROOT}/tools/snapshot" init || printf '    (snapshots not configured - run tools/snapshot init)\n'

  # The single-pane console: bind-mounted into Malcolm's own nginx, so it needs
  # no process of its own.
  "${REPO_ROOT}/tools/dashboard" install || printf '    (console not installed - run tools/dashboard install)\n'

  # Continuous sampling of the watcher threads. The stalls this catches are
  # invisible to docker: the container stays healthy while a thread inside it
  # stops.
  "${REPO_ROOT}/tools/stall-probe" start || true

  cat <<EOF

    Run the watchdog on a timer - it is what repairs the silent stalls:
      while true; do tools/watchdog --heal; sleep 300; done &
    Keep the console's status feed fresh:
      tools/dashboard watch 60 &
    Prove the backups actually restore, rather than assuming:
      tools/snapshot verify
EOF
}

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
  ops)       run_ops ;;
  all)       run_router; run_collector; run_sensor; run_ops ;;
  *) echo "usage: $0 [all|router|collector|sensor|ops|mitm]" >&2; exit 1 ;;
esac
