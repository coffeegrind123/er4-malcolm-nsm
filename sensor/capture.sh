#!/bin/sh
# Stream full-packet capture from the EdgeRouter over SSH and land rotated
# pcap files in Malcolm's upload directory.
#
# The router is the capture point (it is the routing chokepoint and sees
# pre-NAT LAN source addresses). Nothing is written to router flash: the
# capture is streamed over stdout, so eMMC wear and the router's 2.8G of
# free space are both non-issues.
set -u

ROUTER_HOST="${ROUTER_HOST:-192.168.1.1}"
ROUTER_USER="${ROUTER_USER:-admin}"
IFACE="${IFACE:-br0}"
ROTATE_SECS="${ROTATE_SECS:-60}"
COLLECTOR_IP="${COLLECTOR_IP:-192.168.1.100}"
SNAPLEN="${SNAPLEN:-0}"
RBUF="${RBUF:-8192}"
STAGING="${STAGING:-/pcap/staging}"
UPLOAD="${UPLOAD:-/pcap/upload}"

mkdir -p "$STAGING" "$UPLOAD"

# The bind-mounted key arrives with mount-wide permissions that OpenSSH
# rejects, so copy it somewhere private and lock it down.
mkdir -p /tmp/ssh && chmod 700 /tmp/ssh
cp /keys/sensor_key /tmp/ssh/id && chmod 600 /tmp/ssh/id
cp /keys/known_hosts /tmp/ssh/known_hosts && chmod 644 /tmp/ssh/known_hosts

# Exclude the capture transport itself. Without this the stream feeds on its
# own traffic: every captured byte is shipped over the same link, which is
# then captured again.
FILTER="not (host ${ROUTER_HOST} and host ${COLLECTOR_IP} and tcp port 22)"
if [ -n "${EXTRA_BPF:-}" ]; then
  FILTER="(${FILTER}) and (${EXTRA_BPF})"
fi

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*"; }

# Recover captures orphaned by a previous stop. tcpdump's -z hook only runs when
# it rotates a file itself, so whatever it was writing when the container was
# killed is stranded in staging forever - no process will ever move it, and the
# traffic in it is simply lost. Sweep those into upload on startup.
#
# Skip anything currently being written: with the sensor already running this
# would otherwise hand a half-written capture to the pipeline.
orphans=0
for f in "$STAGING"/*.pcap; do
  [ -f "$f" ] || continue
  # older than one rotation interval => cannot be the live file
  if [ -z "$(find "$f" -newermt "-${ROTATE_SECS} seconds" 2>/dev/null)" ]; then
    size=$(wc -c < "$f" 2>/dev/null || echo 0)
    if [ "$size" -gt 24 ]; then
      mv "$f" "${UPLOAD}/$(basename "$f")" && orphans=$((orphans + 1))
    else
      rm -f "$f"
    fi
  fi
done
[ "$orphans" -gt 0 ] && log "recovered ${orphans} orphaned capture(s) from a previous stop"

log "sensor starting: ${ROUTER_USER}@${ROUTER_HOST} iface=${IFACE} snaplen=${SNAPLEN} rotate=${ROTATE_SECS}s"
log "BPF: ${FILTER}"

backoff=2
while true; do
  ssh -i /tmp/ssh/id \
      -o UserKnownHostsFile=/tmp/ssh/known_hosts \
      -o StrictHostKeyChecking=yes \
      -o PasswordAuthentication=no \
      -o PubkeyAcceptedKeyTypes=+ssh-rsa \
      -o HostKeyAlgorithms=+ssh-rsa \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
      -o ConnectTimeout=15 -o LogLevel=ERROR \
      "${ROUTER_USER}@${ROUTER_HOST}" \
      "sudo -n /usr/sbin/tcpdump -i ${IFACE} -s ${SNAPLEN} -U -B ${RBUF} -w - '${FILTER}'" \
    | tcpdump -r - -w "${STAGING}/er4_%Y%m%d-%H%M%S.pcap" \
              -G "${ROTATE_SECS}" -z /usr/local/bin/rotate.sh

  log "capture pipeline exited; reconnecting in ${backoff}s"
  sleep "$backoff"
  backoff=$((backoff * 2))
  [ "$backoff" -gt 60 ] && backoff=60
done
