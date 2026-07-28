#!/bin/sh
# Sampler half of tools/stall-probe. Runs inside a --pid=host container so it can
# read /proc for processes that live in OTHER containers; emits one JSON object
# per line on stdout, which the json-file log driver keeps for `stall-probe report`.
#
# Why sampling rather than a one-shot dump: the stalls are the thing being
# measured, and by the time a human (or the watchdog) notices one, the evidence
# has usually been restarted away. A cheap continuous sample means the state at
# the moment of the stall is already recorded when we go looking.
#
# Nothing here writes to the pipeline's spool directories. The write probe uses
# its own dot-directory, because a stray file in upload/ or processed/ would be
# picked up as a capture.
set -u

SAMPLE_SECS="${SAMPLE_SECS:-2}"
LAT_SECS="${LAT_SECS:-30}"
PCAP="${PCAP:-/pcap}"

# TIMING WITHOUT A PACKAGE INSTALL.
#
# busybox `date` has no %N, so sub-second work would all measure as zero. The
# obvious fix - `apk add coreutils` for GNU date - HANGS in this container:
# --pid=host --privileged and apk's network fetch do not get along, and it hangs
# rather than failing, so the sampler produced no output at all and still looked
# healthy. (Exactly the class of silent failure this repo keeps running into.)
#
# /proc/uptime is a builtin read with no fork and 10 ms resolution. Coarse for a
# 1.5 ms stat, so the fast operations are timed as a BATCH and divided - which
# is better methodology anyway, since it averages out scheduler noise.
STAT_BATCH="${STAT_BATCH:-200}"
CREATE_BATCH="${CREATE_BATCH:-20}"

# centiseconds since boot, as an integer
uptime_cs() { read -r u _ < /proc/uptime; echo "${u%.*}${u#*.}"; }

emit() { printf '%s\n' "$*"; }

emit "{\"t\":$(date -u +%s),\"k\":\"start\",\"sample_secs\":${SAMPLE_SECS},\"lat_secs\":${LAT_SECS},\"stat_batch\":${STAT_BATCH}}"

mkdir -p "${PCAP}/.probe" 2>/dev/null

last_lat=0
while true; do
  ts=$(date -u +%s)

  # ---- thread state of every watcher we care about --------------------------
  # Re-discovered every cycle on purpose: pcap-monitor is restarted by the
  # watchdog, so a pid cached at startup would silently stop existing and the
  # probe would report nothing while looking like it was working.
  ps -eo pid,args 2>/dev/null | while read -r pid rest; do
    # Match the interpreter, not just the string. Without this the probe
    # matches ITS OWN docker client: the command passed to `docker run ... sh -c`
    # contains "pcap_watcher.py", so the docker CLI process argv does too, and it
    # gets labelled as the publisher - complete with its threads and its cwd.
    case "$rest" in python*) ;; *) continue ;; esac
    case "$rest" in
      *pcap_watcher.py*)               role=publisher ;;
      *watch-pcap-uploads-folder.py*)  role=mover ;;
      *filebeat-watch-zeeklogs*)       role=zeek-extract ;;
      *) continue ;;
    esac
    [ -d "/proc/$pid/task" ] || continue
    for t in /proc/"$pid"/task/*; do
      [ -d "$t" ] || continue
      tid="${t##*/}"
      comm=$(cat "$t/comm" 2>/dev/null | tr -d '"')
      # field 3 of stat is the state letter: R running, S sleeping,
      # D uninterruptible (blocked in the kernel, which is what a wedged
      # filesystem call looks like).
      st=$(awk '{print $3}' "$t/stat" 2>/dev/null)
      # wchan is the kernel symbol the thread is parked in. p9_client_rpc means
      # it is waiting on the 9p transport to the Windows host - the hypothesis
      # this probe exists to settle.
      wc=$(cat "$t/wchan" 2>/dev/null | tr -d '\0"')
      sc=$(cut -d' ' -f1 "$t/syscall" 2>/dev/null)
      emit "{\"t\":${ts},\"k\":\"thr\",\"role\":\"${role}\",\"pid\":${pid},\"tid\":${tid},\"comm\":\"${comm:-?}\",\"st\":\"${st:-?}\",\"wchan\":\"${wc:-0}\",\"sc\":\"${sc:-?}\"}"
    done
  done

  # ---- filesystem latency + pipeline liveness -------------------------------
  if [ $((ts - last_lat)) -ge "$LAT_SECS" ]; then
    last_lat=$ts

    a=$(uptime_cs); files=$(ls -1 "${PCAP}/processed" 2>/dev/null); b=$(uptime_cs)
    listdir_us=$(( (b - a) * 10000 ))

    # One file, statted STAT_BATCH times. Repeating one path rather than walking
    # many is deliberate: it measures the 9p round trip, not the directory's
    # size, so the number stays comparable as the archive grows.
    victim=$(printf '%s\n' "$files" | head -1)
    stat_us=-1
    if [ -n "$victim" ]; then
      i=0; c=$(uptime_cs)
      while [ "$i" -lt "$STAT_BATCH" ]; do
        stat -c %s "${PCAP}/processed/${victim}" >/dev/null 2>&1
        i=$((i + 1))
      done
      d=$(uptime_cs)
      stat_us=$(( (d - c) * 10000 / STAT_BATCH ))
    fi

    i=0; e=$(uptime_cs)
    while [ "$i" -lt "$CREATE_BATCH" ]; do
      : > "${PCAP}/.probe/w${i}" 2>/dev/null
      i=$((i + 1))
    done
    f2=$(uptime_cs)
    create_us=$(( (f2 - e) * 10000 / CREATE_BATCH ))
    rm -f "${PCAP}"/.probe/w* 2>/dev/null

    count=$(printf '%s\n' "$files" | grep -c '\.pcap$')
    up=$(ls -1 "${PCAP}/upload" 2>/dev/null | grep -c '\.pcap$')
    newest=$(ls -t "${PCAP}/processed"/*.pcap 2>/dev/null | head -1)
    newest_age=-1
    [ -n "$newest" ] && newest_age=$(( ts - $(stat -c %Y "$newest" 2>/dev/null || echo "$ts") ))

    emit "{\"t\":${ts},\"k\":\"fs\",\"listdir_us\":${listdir_us},\"stat_us\":${stat_us},\"create_us\":${create_us},\"entries\":${count:-0},\"upload\":${up:-0},\"newest_age\":${newest_age}}"
  fi

  sleep "$SAMPLE_SECS"
done
