#!/usr/bin/env bash
# Policy-route selected clients through the interception node.
#
#   router/setup-mitm-route.sh          apply
#   router/setup-mitm-route.sh --status show current state
#   router/setup-mitm-route.sh --remove undo everything
#
# ROUTE, do not DNAT. mitmproxy recovers the original destination via
# SO_ORIGINAL_DST, which is populated by a *local* iptables REDIRECT on the
# interception node. A DNAT here would rewrite the destination before the packet
# ever left the router, and the proxy would have no idea where the client was
# going. Policy routing leaves the destination intact and only changes the next
# hop, which is the whole trick.
#
# FAIL OPEN. A policy route pointing at a dead tunnel is a blackhole: the client
# loses the internet entirely and the cause is not obvious. Every rule installed
# here is conditional on the tunnel being up, and --remove is a single command.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${REPO_ROOT}/config.env"

KEY="${REPO_ROOT}/keys/sensor_key"
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o PasswordAuthentication=no
          -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa)
rsh() { ssh "${SSH_OPTS[@]}" "${ROUTER_USER}@${ROUTER_HOST}" "$@"; }

TUN_IF="${MITM_TUNNEL_IF:-awg0}"
TABLE="${MITM_ROUTE_TABLE:-101}"
MARK="${MITM_FWMARK:-0x4d}"
CLIENTS="${MITM_CLIENTS:-}"
PORTS="${MITM_INTERCEPT_PORTS:-80 443}"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m   %s\n' "$*"; }
warn() { printf '    \033[33mwarn\033[0m %s\n' "$*"; }
die()  { printf '    \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

case "${1:-apply}" in
--status)
  say "Interception routing state on ${ROUTER_HOST}"
  rsh "echo '  --- tunnel ---'; ip -br addr show ${TUN_IF} 2>/dev/null || echo '  ${TUN_IF} absent'
       echo '  --- rules ---'; ip rule show | grep -E 'fwmark|${TABLE}' || echo '  none'
       echo '  --- table ${TABLE} ---'; ip route show table ${TABLE} 2>/dev/null || echo '  empty'
       echo '  --- marking rules ---'; sudo iptables -t mangle -S PREROUTING 2>/dev/null | grep -i mitm || echo '  none'"
  exit 0 ;;

--remove)
  say "Removing interception routing"
  rsh "sudo iptables -t mangle -S PREROUTING 2>/dev/null | grep -i mitm | sed 's/^-A/-D/' \
         | while read -r r; do sudo iptables -t mangle \$r 2>/dev/null || true; done
       sudo ip rule del fwmark ${MARK} table ${TABLE} 2>/dev/null || true
       sudo ip route flush table ${TABLE} 2>/dev/null || true"
  ok "routing removed - traffic returns to the normal path"
  echo "    (the tunnel interface itself is left alone; remove it in EdgeOS config if unwanted)"
  exit 0 ;;
esac

[[ -n "$CLIENTS" ]] || die "MITM_CLIENTS is empty - refusing to intercept the entire LAN by default"

say "Preflight"
rsh true >/dev/null 2>&1 || die "cannot reach ${ROUTER_USER}@${ROUTER_HOST}"
ok "router reachable"

# The whole design depends on this interface existing and being up. If it is
# not, installing the rules would blackhole every client listed.
if ! rsh "ip link show ${TUN_IF} 2>/dev/null | grep -q 'state UP\|UNKNOWN'"; then
  die "tunnel ${TUN_IF} is not up. Bring it up first (EdgeOS: set interfaces amneziawg ${TUN_IF} ...).
       Refusing to install policy routes that would blackhole: ${CLIENTS}"
fi
ok "tunnel ${TUN_IF} is up"

PEER=$(rsh "ip -4 route show dev ${TUN_IF} 2>/dev/null | awk '/via/{print \$3; exit}'" || true)
[[ -n "$PEER" ]] || PEER="${MITM_PEER_IP:-}"
[[ -n "$PEER" ]] || die "cannot determine the far side of ${TUN_IF}; set MITM_PEER_IP in config.env"
ok "interception node reachable at ${PEER} over ${TUN_IF}"

say "Installing policy routes"
rsh "sudo ip route replace default via ${PEER} dev ${TUN_IF} table ${TABLE}"
ok "table ${TABLE}: default via ${PEER}"

rsh "sudo ip rule del fwmark ${MARK} table ${TABLE} 2>/dev/null || true
     sudo ip rule add fwmark ${MARK} table ${TABLE} priority 100"
ok "fwmark ${MARK} -> table ${TABLE}"

for client in $CLIENTS; do
  for port in $PORTS; do
    rsh "sudo iptables -t mangle -C PREROUTING -s ${client} -p tcp --dport ${port} \
           -m comment --comment mitm -j MARK --set-mark ${MARK} 2>/dev/null \
         || sudo iptables -t mangle -A PREROUTING -s ${client} -p tcp --dport ${port} \
              -m comment --comment mitm -j MARK --set-mark ${MARK}"
  done
  ok "marking ${client} tcp/${PORTS// /,}"
done

cat <<EOF

$(printf '\033[1m==> Interception routing active.\033[0m')
    Clients : ${CLIENTS}
    Ports   : ${PORTS}
    Path    : mark ${MARK} -> table ${TABLE} -> ${PEER} via ${TUN_IF}

    Those clients need the CA installed or TLS will fail for them:
      ${REPO_ROOT}/mitm/ca/mitmproxy-ca-cert.pem

    Certificate-pinned devices (IoT especially) will stop working rather than
    be intercepted. Exclude them from MITM_CLIENTS.

    Undo:  router/setup-mitm-route.sh --remove
    State: router/setup-mitm-route.sh --status
EOF
