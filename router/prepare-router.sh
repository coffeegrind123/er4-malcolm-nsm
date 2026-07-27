#!/usr/bin/env bash
# Prepare an EdgeRouter as a capture sensor.
#
# Idempotent: safe to re-run. Password auth is used once to install a key, then
# everything else runs over the key.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${REPO_ROOT}/config.env"

KEYS_DIR="${REPO_ROOT}/keys"
KEY="${KEYS_DIR}/sensor_key"

# EdgeOS ships an old OpenSSH. Modern clients disable these by default, and the
# failure is an unhelpful "no matching host key type" or "Permission denied".
SSH_COMPAT=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o ConnectTimeout=15
  -o KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1
  -o HostKeyAlgorithms=+ssh-rsa,ssh-dss
  -o PubkeyAcceptedKeyTypes=+ssh-rsa
)

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m   %s\n' "$*"; }
warn() { printf '    \033[33mwarn\033[0m %s\n' "$*"; }
die()  { printf '    \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

pw_ssh()  { sshpass -e ssh "${SSH_COMPAT[@]}" -o PubkeyAuthentication=no "${ROUTER_USER}@${ROUTER_HOST}" "$@"; }
key_ssh() { ssh -i "$KEY" "${SSH_COMPAT[@]}" -o PasswordAuthentication=no "${ROUTER_USER}@${ROUTER_HOST}" "$@"; }

command -v sshpass >/dev/null || die "sshpass not installed (apt-get install -y sshpass)"

if [[ -z "${ROUTER_PASS:-}" ]]; then
  read -rsp "Password for ${ROUTER_USER}@${ROUTER_HOST}: " ROUTER_PASS; echo
fi
export SSHPASS="$ROUTER_PASS"

# ---------------------------------------------------------------------------
say "Preflight: can this router actually capture?"

pw_ssh true >/dev/null 2>&1 || die "cannot log in to ${ROUTER_USER}@${ROUTER_HOST}"
ok "password login works"

# `command -v tcpdump` lies here: the login PATH omits /usr/sbin, so a perfectly
# present tcpdump reports as missing. Test the path directly.
if pw_ssh 'test -x /usr/sbin/tcpdump' 2>/dev/null; then
  ok "tcpdump present: $(pw_ssh '/usr/sbin/tcpdump --version 2>&1 | head -1')"
else
  die "/usr/sbin/tcpdump not found - install it before continuing"
fi

pw_ssh 'sudo -n true' 2>/dev/null || die "passwordless sudo required for ${ROUTER_USER}"
ok "passwordless sudo works"

# THE make-or-break check. With hardware offload enabled, forwarded packets are
# switched in the Cavium/Octeon fastpath and never traverse the Linux stack, so
# libpcap sees almost nothing and the capture looks mysteriously empty.
if pw_ssh 'grep -q "offload" /config/config.boot' 2>/dev/null; then
  warn "an 'offload' block exists in /config/config.boot - inspect it:"
  pw_ssh 'grep -A8 offload /config/config.boot' | sed 's/^/      /'
  warn "if hwnat/ipsec offload is enabled, capture will MISS forwarded traffic"
else
  ok "no offload block - all forwarded traffic traverses the Linux stack"
fi

pw_ssh "ip link show ${CAPTURE_IFACE} >/dev/null 2>&1" || die "interface ${CAPTURE_IFACE} not found"
ok "capture interface ${CAPTURE_IFACE} exists"

# ---------------------------------------------------------------------------
say "Fixing home directory ownership"

# EdgeOS can leave /home/<user> owned by a stale UID from a previous account.
# Under `StrictModes yes` OpenSSH refuses to read authorized_keys when the home
# or .ssh directory is owned by neither root nor the authenticating user, so key
# auth fails with a bare "Permission denied" and no server-side log entry.
UID_NOW=$(pw_ssh 'id -u')
GID_NOW=$(pw_ssh 'id -g')
HOME_OWNER=$(pw_ssh 'stat -c %u "$HOME"' 2>/dev/null || echo "?")
if [[ "$HOME_OWNER" != "$UID_NOW" ]]; then
  warn "home owned by uid ${HOME_OWNER} but ${ROUTER_USER} is uid ${UID_NOW} - fixing"
  pw_ssh "sudo chown -R ${UID_NOW}:${GID_NOW} \$HOME"
  ok "chowned home to ${UID_NOW}:${GID_NOW}"
else
  ok "home ownership already correct (uid ${UID_NOW})"
fi

# ---------------------------------------------------------------------------
say "Installing capture SSH key"

mkdir -p "$KEYS_DIR"; chmod 700 "$KEYS_DIR"
if [[ ! -f "$KEY" ]]; then
  # RSA, not ed25519: EdgeOS's config parser accepts ssh-rsa reliably.
  ssh-keygen -t rsa -b 2048 -N '' -C 'malcolm-sensor' -f "$KEY" >/dev/null
  ok "generated $KEY"
else
  ok "reusing existing $KEY"
fi
chmod 600 "$KEY"

PUBKEY=$(awk '{print $2}' "${KEY}.pub")
# Written through the EdgeOS config tree, not straight into authorized_keys:
# a later `commit` regenerates that file and would discard a raw edit.
pw_ssh "vbash -c 'source /opt/vyatta/etc/functions/script-template
configure
set system login user ${ROUTER_USER} authentication public-keys malcolm-sensor type ssh-rsa
set system login user ${ROUTER_USER} authentication public-keys malcolm-sensor key ${PUBKEY}
commit
save
exit'" >/dev/null
ok "key installed via EdgeOS config and saved"

ssh-keyscan -t rsa,ecdsa,ed25519 "$ROUTER_HOST" 2>/dev/null > "${KEYS_DIR}/known_hosts"
ok "pinned router host keys ($(wc -l < "${KEYS_DIR}/known_hosts") entries)"

key_ssh 'echo ok' >/dev/null 2>&1 || die "key auth still failing - check StrictModes and home ownership"
ok "key authentication verified"

# ---------------------------------------------------------------------------
say "Measuring baseline capture rate"

# Busybox coreutils on EdgeOS has no `timeout`, so background-and-kill instead.
STATS=$(key_ssh "sudo sh -c '/usr/sbin/tcpdump -i ${CAPTURE_IFACE} -n -w /tmp/_probe.pcap \
    \"not (host ${ROUTER_HOST} and host ${COLLECTOR_IP} and tcp port 22)\" >/dev/null 2>/tmp/_probe.err & echo \$! >/tmp/_probe.pid'
sleep 10
sudo sh -c 'kill \$(cat /tmp/_probe.pid) 2>/dev/null'
sleep 1
cat /tmp/_probe.err
echo \"BYTES=\$(wc -c < /tmp/_probe.pcap)\"
sudo rm -f /tmp/_probe.pcap /tmp/_probe.err /tmp/_probe.pid" 2>/dev/null)

echo "$STATS" | grep -E 'packets (captured|dropped)' | sed 's/^/      /'
BYTES=$(echo "$STATS" | sed -n 's/^BYTES=//p')
if [[ -n "$BYTES" && "$BYTES" -gt 24 ]]; then
  ok "captured ${BYTES} bytes in 10s (~$(( BYTES * 8640 / 1000000000 )) GB/day at full snaplen)"
else
  warn "captured almost nothing - verify ${CAPTURE_IFACE} carries traffic"
fi
echo "$STATS" | grep -q '0 packets dropped by kernel' \
  && ok "no kernel drops" \
  || warn "kernel drops observed - raise RBUF in config.env"

say "Router ready."
