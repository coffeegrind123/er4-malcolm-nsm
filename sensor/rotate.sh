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

mv "$f" "${UPLOAD}/$(basename "$f")"
