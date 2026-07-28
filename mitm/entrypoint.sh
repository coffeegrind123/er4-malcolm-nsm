#!/bin/bash
# Bring up the interception node: tunnel endpoint, local redirect, mitmproxy.
#
# MODE=proxy        explicit HTTP proxy on 8080. No router changes, nothing in
#                   the path of other traffic. Use this first - it proves the CA
#                   and the decryption work before anything is redirected.
# MODE=transparent  tunnel + REDIRECT + transparent proxy. Router policy-routes
#                   selected clients in. This is the network-wide mode.
set -euo pipefail

MODE="${MODE:-proxy}"
LISTEN_PORT="${LISTEN_PORT:-8080}"
WEB_PORT="${WEB_PORT:-8081}"
CA_DIR="${CA_DIR:-/ca}"
KEYLOG="${KEYLOG:-/keylog/sslkeys.log}"
TUNNEL_IF="${TUNNEL_IF:-wg0}"
TUNNEL_CONF="${TUNNEL_CONF:-/wg/wg0.conf}"

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] mitm: $*"; }

mkdir -p "$CA_DIR" "$(dirname "$KEYLOG")"

# The TLS master secrets are the whole point of this node. mitmproxy writes them
# here, and Arkime/Zeek use them to decrypt the pcaps the router already
# captured - so decrypted traffic shows up in the existing Malcolm UI rather
# than in a second, disconnected tool.
export SSLKEYLOGFILE="$KEYLOG"
log "TLS secrets -> ${KEYLOG}"

if [[ "$MODE" == "transparent" ]]; then
  if [[ ! -f "$TUNNEL_CONF" ]]; then
    log "FATAL: MODE=transparent but ${TUNNEL_CONF} is missing"
    exit 1
  fi

  log "starting tunnel ${TUNNEL_IF}"
  # Userspace implementation: the Docker Desktop kernel has no wireguard module.
  export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
  wg-quick up "$TUNNEL_CONF" || { log "FATAL: tunnel failed to come up"; exit 1; }

  # Redirect intercepted ports to the proxy. This MUST be local: it is what
  # populates SO_ORIGINAL_DST so mitmproxy learns the real destination.
  for port in ${INTERCEPT_PORTS:-80 443}; do
    iptables -t nat -A PREROUTING -i "$TUNNEL_IF" -p tcp --dport "$port" \
             -j REDIRECT --to-port "$LISTEN_PORT"
    log "redirecting tcp/${port} -> ${LISTEN_PORT}"
  done

  # Everything not redirected still has to reach the internet, or the clients
  # being routed through here lose all their non-intercepted traffic.
  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || \
    log "WARN: could not set ip_forward (pass --sysctl net.ipv4.ip_forward=1)"

  exec mitmdump \
    --mode transparent \
    --listen-port "$LISTEN_PORT" \
    --set confdir="$CA_DIR" \
    --set block_global=false \
    ${MITM_EXTRA_ARGS:-}
fi

log "explicit proxy on ${LISTEN_PORT} (no traffic is redirected in this mode)"
exec mitmweb \
  --mode regular \
  --listen-port "$LISTEN_PORT" \
  --web-host 0.0.0.0 --web-port "$WEB_PORT" \
  --set confdir="$CA_DIR" \
  --set block_global=false \
  ${MITM_EXTRA_ARGS:-}
