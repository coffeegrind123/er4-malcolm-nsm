#!/bin/sh
# tcpdump -z hook: invoked with the pcap file it has just closed.
#
# Staging and upload sit on the same filesystem, so this is a rename rather
# than a copy. Malcolm's pcap-monitor therefore never observes a partially
# written file -- the capture appears at its final path complete or not at all.
set -u
UPLOAD="${UPLOAD:-/pcap/upload}"
f="$1"

[ -f "$f" ] || exit 0

# A rotation with no traffic still produces a 24-byte pcap header. Feeding
# those to Malcolm creates a stream of empty ingest jobs.
size=$(wc -c < "$f" 2>/dev/null || echo 0)
if [ "$size" -le 24 ]; then
  rm -f "$f"
  exit 0
fi

# Oversized captures wedge the downstream mover. A traffic burst inside one
# rotation window can produce a file an order of magnitude past the norm - the
# observed distribution was median 0.9 MB, p95 38 MB, and a 156 MB outlier that
# stalled the pipeline for over an hour. The mover never even logged it; it
# simply stopped, and every restart re-encountered the same file and stopped
# again.
#
# Quarantine rather than queue. The capture is kept for manual handling, and
# the pipeline keeps moving instead of deadlocking on one file.
MAX_BYTES="${MAX_PCAP_BYTES:-52428800}"
if [ "$size" -gt "$MAX_BYTES" ]; then
  mkdir -p "${QUARANTINE:-/pcap/quarantine}"
  mv "$f" "${QUARANTINE:-/pcap/quarantine}/$(basename "$f")"
  echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] rotate: quarantined $(basename "$f") ($((size/1048576))MB > $((MAX_BYTES/1048576))MB) - would stall the mover"
  exit 0
fi

mv "$f" "${UPLOAD}/$(basename "$f")"
