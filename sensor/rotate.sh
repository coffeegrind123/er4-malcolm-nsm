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

# Very large captures get SPLIT, not discarded.
#
# The history here is worth knowing, because the original rule was aimed at the
# wrong target. A 156 MB capture was blamed for deadlocking the mover for over an
# hour, so anything past 50 MB was quarantined - and quarantine is not storage,
# it is a bin that nothing ever reads. That cost real traffic: four captures in
# seven hours, one of them 1 MB over the line.
#
# Re-measured with tools/pcap-limit, and the size premise does not hold:
#
#   - 14 captures between 50 MB and 106.8 MB are sitting in processed/ and are
#     all present in arkime_files, i.e. they were fully analysed
#   - the very 156 MB capture that was blamed was fed back through the live
#     pipeline and cleared it in 30 seconds - mover 18s, published 30s
#   - the mover logs its 👓 line BEFORE it does any work, yet the incident
#     reported no 👓 at all, which is impossible if the file was what blocked it
#
# So the file was at the head of the queue during one of the silent watcher
# stalls this deployment gets every few hours, and got the blame. The cap is
# therefore now a sanity bound well above anything observed, and crossing it is
# no longer a reason to throw traffic away: a burst that big is split into
# pipeline-sized pieces and queued.
#
# Splitting is cheap and lossless. Rotation already cuts flows at arbitrary
# boundaries every ROTATE_SECS, so a burst arriving as four files instead of one
# is the same class of artefact the pipeline already handles on every capture.
MAX_BYTES="${MAX_PCAP_BYTES:-268435456}"
if [ "$size" -gt "$MAX_BYTES" ]; then
  base=$(basename "$f" .pcap)
  SPLIT_DIR="${SPLIT_DIR:-/pcap/.split}"
  mkdir -p "$SPLIT_DIR"
  rm -f "${SPLIT_DIR}/${base}"* 2>/dev/null

  # -C is in MILLIONS of bytes, not MiB, and it is a rotation threshold rather
  # than a hard cap - chunks land a hair over it, so leave headroom under
  # MAX_BYTES rather than dividing exactly.
  SPLIT_MB="${PCAP_SPLIT_MB:-100}"
  if tcpdump -r "$f" -w "${SPLIT_DIR}/${base}" -C "$SPLIT_MB" 2>/dev/null; then
    # NOTE THE GLOB. tcpdump names the FIRST chunk with no suffix at all
    # ("chunk", then "chunk1", "chunk2"...), so a ${base}[0-9]* pattern silently
    # drops the first 100 MB and reports success. Verified by hand, because that
    # is exactly the kind of loss that never shows up as an error.
    n=0
    for c in "${SPLIT_DIR}/${base}"*; do
      [ -f "$c" ] || continue
      n=$((n + 1))
      # Keep the capture timestamp at the front: the watchdog's stall check and
      # prune-pcap both derive a file's age from the name, never from mtime.
      mv "$c" "${UPLOAD}/${base}-p${n}.pcap"
    done
    if [ "$n" -gt 0 ]; then
      rm -f "$f"
      echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] rotate: split ${base}.pcap ($((size/1048576))MB > $((MAX_BYTES/1048576))MB) into ${n} parts - queued, nothing discarded"
      exit 0
    fi
  fi

  # Splitting failed (corrupt capture, no space). Only now fall back to keeping
  # it aside, and say plainly that it is unanalysed.
  mkdir -p "${QUARANTINE:-/pcap/quarantine}"
  mv "$f" "${QUARANTINE:-/pcap/quarantine}/$(basename "$f")"
  echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] rotate: could not split $(basename "$f") ($((size/1048576))MB) - quarantined UNANALYSED, recover with tools/unquarantine"
  exit 0
fi

mv "$f" "${UPLOAD}/$(basename "$f")"
