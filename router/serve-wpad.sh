#!/usr/bin/env bash
# Serve proxy auto-config (WPAD) and the interception CA from the router.
#
# This automates the half of client setup that CAN be automated. Clients already
# ask for WPAD unprompted - a single Windows host on the test network produced
# 131 wpad lookups, all answered NXDOMAIN - so serving it configures the proxy
# with no client-side action at all.
#
# It does NOT install the CA. Nothing can: a network that could push a trusted
# root would defeat TLS entirely. The CA is served for convenient download and
# must still be installed deliberately on each device.
#
# WPAD is a known attack vector precisely because it is this effective. Enabling
# it means any host able to answer `wpad` can propose a proxy. Only do this on a
# network you control.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${REPO_ROOT}/config.env"

KEY="${REPO_ROOT}/keys/sensor_key"
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o PasswordAuthentication=no
          -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa)
rsh() { ssh "${SSH_OPTS[@]}" "${ROUTER_USER}@${ROUTER_HOST}" "$@"; }

CA_SRC="${REPO_ROOT}/mitm/ca/mitmproxy-ca-cert.pem"
PROXY_HOST="${MITM_PROXY_HOST:-${COLLECTOR_IP}}"
PROXY_PORT="${MITM_LISTEN_PORT:-8080}"
WEBROOT="${ROUTER_WEBROOT:-/var/www/htdocs}"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()  { printf '    \033[32mok\033[0m   %s\n' "$*"; }
die() { printf '    \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

[[ -f "$CA_SRC" ]] || die "CA not found at ${CA_SRC} - start the mitm node once to generate it"

say "Publishing WPAD + CA on ${ROUTER_HOST}"

# The PAC ends with DIRECT deliberately. If the proxy is unreachable the client
# falls back to browsing normally instead of losing the network - the same
# fail-open rule that governs the transparent-mode routes.
PAC=$(cat <<PACEOF
function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0",  "255.0.0.0")   ||
        isInNet(dnsResolve(host), "172.16.0.0","255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0","255.255.0.0")) {
        return "DIRECT";
    }
    return "PROXY ${PROXY_HOST}:${PROXY_PORT}; DIRECT";
}
PACEOF
)

rsh "sudo mkdir -p ${WEBROOT}"
printf '%s\n' "$PAC" | rsh "sudo tee ${WEBROOT}/wpad.dat >/dev/null"
rsh "sudo cp ${WEBROOT}/wpad.dat ${WEBROOT}/proxy.pac 2>/dev/null || true"
ok "wpad.dat published (proxy ${PROXY_HOST}:${PROXY_PORT}, DIRECT fallback)"

# shellcheck disable=SC2002
cat "$CA_SRC" | rsh "sudo tee ${WEBROOT}/mitm-ca.crt >/dev/null"
ok "CA published at http://${ROUTER_HOST}/mitm-ca.crt"

# WPAD is found by resolving the name `wpad` in the local domain, so it has to
# resolve to the router. Without this the PAC file is served but never fetched.
rsh "vbash -c 'source /opt/vyatta/etc/functions/script-template
configure
set system static-host-mapping host-name wpad inet ${ROUTER_HOST}
commit
save
exit'" >/dev/null 2>&1 && ok "wpad resolves to ${ROUTER_HOST}" \
  || echo "    warn: could not add static host mapping - add 'wpad' -> ${ROUTER_HOST} manually"

cat <<EOF

$(printf '\033[1m==> Published.\033[0m')
    Install the CA on each client you intend to intercept:
      http://${ROUTER_HOST}/mitm-ca.crt

    Windows: certlm.msc -> Trusted Root Certification Authorities -> Import
    Clients honouring WPAD will pick up the proxy automatically; the PAC falls
    back to DIRECT so a dead proxy does not take the network with it.

    To undo:
      ssh ${ROUTER_USER}@${ROUTER_HOST} "sudo rm -f ${WEBROOT}/wpad.dat ${WEBROOT}/proxy.pac ${WEBROOT}/mitm-ca.crt"
EOF
