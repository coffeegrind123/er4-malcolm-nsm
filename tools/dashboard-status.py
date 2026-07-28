#!/usr/bin/env python3
"""Collect the pipeline-health facts that no Malcolm API exposes, as JSON.

Run by `tools/dashboard status`, which the watchdog loop calls. The dashboard
page fetches the result every DASHBOARD_REFRESH_SECS.

WHY THIS FILE EXISTS AT ALL

Malcolm ships OpenSearch Dashboards and Arkime, and both are good at the
question "what is on the network". Neither can answer "is the pipeline
healthy", because the things that break here are invisible to them:

  * a watcher thread dies and its queue stops draining - containers stay healthy
  * the host runs out of memory and OpenSearch reports it as a corrupt index
  * captures pile up in a spool directory nothing is polling
  * a snapshot has not been taken, or has never been proven to restore

All of that lives in /proc, in `docker`, on the filesystem and in this repo's
own tools - not in an index. This is the bridge.

WHAT IT MUST NOT DO

It runs every refresh interval on a host that has no memory headroom and a 9p
mount that is 60-100x slower than local disk, so:

  * no directory walks of pcap/processed - the count comes from the stall probe,
    which already pays that cost once per its own cycle
  * aggregate counts, never per-file stats
  * every external call is time-bounded; a hung docker call must not wedge the
    refresh loop and leave a permanently stale page
"""
from __future__ import annotations

import calendar
import json
import os
import pathlib
import re
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _config import load_config_env  # noqa: E402

load_config_env()

HERE = pathlib.Path(__file__).resolve().parent
STATE_DIR = pathlib.Path(os.environ.get("STATE_DIR") or (os.environ.get("TMPDIR") or "/tmp") + "/er4-watchdog")
FORENSICS = STATE_DIR / "forensics"
PROBE = os.environ.get("PROBE_CONTAINER", "er4-stall-probe")
SETTLE_SEC = int(os.environ.get("PCAP_SETTLE_SEC", "10"))


def run(cmd, timeout=20, shell=False):
    """Never let a slow docker call stall the refresh. A missing value shows as
    'unknown' on the page, which is honest; a hung collector shows as a page
    that silently stops updating, which is not."""
    try:
        p = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=timeout
        )
        return p.stdout.strip()
    except Exception:
        return ""


# TTL CACHE for the slow-moving, expensive facts.
#
# Measured: a full collection takes ~17s, almost all of it `docker stats`,
# `docker run` and three osapi round trips. At a 60s refresh that is a ~30% duty
# cycle of docker calls on a host whose defining problem is that it has no
# headroom - the monitoring would become a measurable part of what it monitors,
# which is this deployment's oldest lesson in a new form.
#
# So: memory, threads and queue depth are collected every refresh because they
# change on that timescale and are cheap. Cluster stats, snapshot inventory and
# the container memory table are cached - none of them can change meaningfully
# inside five minutes, and a stale value is labelled with its age rather than
# silently presented as current.
CACHE_DIR = STATE_DIR / "dashboard-cache"


def cached(name, ttl, fn):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / f"{name}.json"
    now = time.time()
    try:
        if path.exists() and now - path.stat().st_mtime < ttl:
            d = json.loads(path.read_text())
            d["_age_sec"] = int(now - path.stat().st_mtime)
            return d
    except Exception:
        pass
    val = fn()
    if not isinstance(val, dict):
        val = {"value": val}
    try:
        path.write_text(json.dumps(val))
    except Exception:
        pass
    val["_age_sec"] = 0
    return val


def meminfo():
    vals = {}
    try:
        for line in open("/proc/meminfo"):
            k, _, v = line.partition(":")
            vals[k] = int(v.split()[0]) // 1024
    except Exception:
        return {}
    total, free = vals.get("MemTotal", 0), vals.get("MemFree", 0)
    avail = vals.get("MemAvailable", 0)
    st, sf = vals.get("SwapTotal", 0), vals.get("SwapFree", 0)
    return {
        "total_mb": total,
        "free_mb": free,
        "avail_mb": avail,
        "cached_mb": vals.get("Cached", 0),
        "swap_pct": round((st - sf) * 100 / st) if st else 0,
        "floor_avail_mb": int(os.environ.get("MEM_WARN_MB", 1400)),
        "floor_free_mb": int(os.environ.get("MEM_FREE_WARN_MB", 800)),
    }


def mem_trend():
    """The sample history tools/memguard keeps. The trend is the whole point of
    that file: with ~190 MB between routine load and the reading at which an
    index was destroyed, a level gauge cannot warn early but a slope can."""
    samples, path = [], STATE_DIR / "memory.samples"
    if path.exists():
        try:
            for line in path.read_text().splitlines()[-240:]:
                f = line.split()
                if len(f) >= 4:
                    samples.append([int(f[0]), int(f[1]), int(f[2]), int(f[3])])
        except Exception:
            pass
    eta = run([str(HERE / "memguard"), "--eta"], timeout=15).split()
    return {
        "samples": samples,
        "avail_eta_min": int(float(eta[0])) if len(eta) > 0 and eta[0] not in ("", "-1") else -1,
        "free_eta_min": int(float(eta[1])) if len(eta) > 1 and eta[1] not in ("", "-1") else -1,
    }


def consumers():
    out = run(["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.MemUsage}}"], timeout=25)
    rows = []
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, usage = line.split("\t", 1)
        m = re.match(r"([\d.]+)\s*([KMG]i?B)", usage.strip())
        if not m:
            continue
        v = float(m.group(1))
        unit = m.group(2)
        mb = v * 1024 if unit.startswith("G") else v / 1024 if unit.startswith("K") else v
        # Mark our own containers so the console can collapse them into one row.
        # Everything the monitoring stack runs: the Malcolm compose project, the
        # sensor and probe, and the agent session that is driving all this.
        project = os.environ.get("COMPOSE_PROJECT") or os.path.basename(
            os.environ.get("MALCOLM_DIR", "malcolm").rstrip("/"))
        ours = name.startswith(project + "-") or name.startswith("er4-") or name == "claude"
        rows.append({"name": name, "mb": round(mb), "stack": bool(ours)})
    rows.sort(key=lambda r: -r["mb"])
    return rows[:14]


def watchers():
    """Thread census with the learned healthy peak alongside it.

    A watcher below its peak with nothing draining is the failure mode that took
    months to pin down: a thread dies, the queue stops, and every container still
    reports healthy. The peak is learned by tools/watchdog only from watchers
    that are demonstrably working - a baseline sampled during the fault is not a
    baseline."""
    rows = []
    for line in run([str(HERE / "stall-probe"), "threads"], timeout=30).splitlines():
        f = line.split()
        if len(f) != 3:
            continue
        role, count, age = f[0], int(f[1]), int(f[2])
        peak_file = STATE_DIR / f"threads.{role}"
        peak = 0
        try:
            peak = int(peak_file.read_text().strip())
        except Exception:
            pass
        rows.append({
            "role": role, "threads": count, "peak": peak, "age_sec": age,
            "degraded": bool(peak and count < peak and age > 120),
        })
    return rows


def probe_fs():
    """9p latency percentiles from the stall probe's own log - no extra IO here.

    The ratio to the settle window is what matters: once a directory scan takes
    longer than PCAP_PIPELINE_POLLING_ASSUME_CLOSED_SEC, the watcher is late by
    construction and it looks exactly like a stall."""
    out = run(["docker", "logs", "--since", "3h", PROBE], timeout=25)
    ld, entries, upload, hist = [], 0, 0, []
    for line in out.splitlines():
        if '"k":"fs"' not in line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        ld.append(d.get("listdir_us", 0) / 1000.0)
        entries, upload = d.get("entries", entries), d.get("upload", upload)
        hist.append([d.get("t", 0), round(d.get("listdir_us", 0) / 1000), d.get("upload", 0)])
    if not ld:
        return {"available": False, "settle_sec": SETTLE_SEC}
    ld.sort()
    def pct(p):
        return ld[min(len(ld) - 1, int(len(ld) * p / 100))]
    retain = int(86400 / int(os.environ.get("ROTATE_SECS", 120))) * int(os.environ.get("PCAP_RETENTION_DAYS", 7))
    per95 = (pct(95) / entries) if entries else 0
    return {
        "available": True, "settle_sec": SETTLE_SEC, "entries": entries, "upload": upload,
        # Downsampled series so the tiles can show a trend rather than a bare
        # level. A number with no history cannot tell you whether it is a spike
        # or the new normal, which is the difference between acting and waiting.
        "history": hist[-60:],
        "listdir_p50_ms": round(pct(50)), "listdir_p95_ms": round(pct(95)), "listdir_max_ms": round(ld[-1]),
        "over_settle": sum(1 for v in ld if v > SETTLE_SEC * 1000), "samples": len(ld),
        "retain_files": retain, "projected_p95_s": round(per95 * retain / 1000, 1),
    }


def queues():
    """Depth AND head age. Depth alone is a bad signal - a deep queue that is
    moving is fine, and restarting it is actively harmful."""
    rows = []
    pcap = os.environ.get("PCAP_MOUNT") or (os.environ.get("DATA_ROOT_WIN", "//d/malcolm-data") + "/pcap")
    zeek = os.environ.get("ZEEK_MOUNT") or (os.environ.get("DATA_ROOT_WIN", "//d/malcolm-data") + "/zeek-logs")
    out = run(["docker", "run", "--rm", "-v", f"{pcap}:/p", "-v", f"{zeek}:/z", "alpine", "sh", "-c",
               'echo "upload $(ls -1 /p/upload/*.pcap 2>/dev/null | wc -l) $(ls -1 /p/upload/*.pcap 2>/dev/null | head -1 | xargs -r basename)"; '
               'echo "quarantine $(ls -1 /p/quarantine/*.pcap 2>/dev/null | wc -l) -"; '
               'echo "zeek $(ls -1 /z/upload/*.tar.gz 2>/dev/null | wc -l) $(ls -1 /z/upload/*.tar.gz 2>/dev/null | head -1 | xargs -r basename)"'],
              timeout=40)
    for line in out.splitlines():
        f = line.split()
        if len(f) < 2:
            continue
        name, pending = f[0], int(f[1])
        head = f[2] if len(f) > 2 else "-"
        age = -1
        # Age from the capture timestamp in the NAME, never mtime: the re-queue
        # repair rewrites mtimes, which would make a stranded file look new.
        m = re.search(r"(20\d{6})-(\d{6})", head or "")
        if m:
            try:
                # timegm, NOT mktime. The capture timestamp in the filename is UTC,
                # and mktime interprets a struct_time as LOCAL time - so on a host
                # at UTC+3 every head age came out three hours too large. Measured:
                # a capture processed 194 seconds after it was written reported as
                # 10,994 seconds old, which was enough to put a false "head is old"
                # warning in the console banner. A plausible number, silently wrong.
                age = int(time.time() - calendar.timegm(time.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")))
            except Exception:
                pass
        rows.append({"name": name, "pending": pending, "head": head, "head_age_sec": age})
    return rows


def snapshots():
    out = run([str(HERE / "osapi"), "es", "GET", "_snapshot/nsm/_all"], timeout=30)
    try:
        snaps = json.loads(out).get("snapshots", [])
    except Exception:
        return {"available": False}
    ok = [s for s in snaps if s.get("state") == "SUCCESS"]
    latest = ok[-1] if ok else None
    age = -1
    if latest and latest.get("start_time_in_millis"):
        age = int(time.time() - latest["start_time_in_millis"] / 1000)
    return {
        "available": True, "count": len(snaps), "successful": len(ok),
        "latest": latest.get("snapshot") if latest else None, "latest_age_sec": age,
    }


def incidents():
    """Every forensics dump the watchdog took before repairing something. This is
    the incident history that exists nowhere else - each file is a stall that was
    caught and healed, and the count over time is the honest stall rate."""
    rows = []
    if FORENSICS.is_dir():
        for p in sorted(FORENSICS.glob("*.txt"))[-40:]:
            m = re.match(r"(\d{8}T\d{6}Z)-(.+)\.txt", p.name)
            if not m:
                continue
            try:
                # Same trap: the dump filenames are UTC (they end in Z).
                t = calendar.timegm(time.strptime(m.group(1), "%Y%m%dT%H%M%SZ"))
            except Exception:
                continue
            rows.append({"t": t, "label": m.group(2), "file": p.name})
    return rows


def cluster():
    out = run([str(HERE / "osapi"), "es", "GET",
               "_cluster/health?filter_path=status,unassigned_shards,active_shards"], timeout=25)
    try:
        h = json.loads(out)
    except Exception:
        return {"reachable": False}
    st = run([str(HERE / "osapi"), "es", "GET",
              "_cluster/stats?filter_path=indices.store.size_in_bytes,indices.docs.count"], timeout=25)
    docs = size = 0
    try:
        d = json.loads(st).get("indices", {})
        docs, size = d.get("docs", {}).get("count", 0), d.get("store", {}).get("size_in_bytes", 0)
    except Exception:
        pass
    return {
        "reachable": True, "status": h.get("status"),
        "unassigned": h.get("unassigned_shards", 0), "active": h.get("active_shards", 0),
        "docs": docs, "size_gb": round(size / 1073741824, 2),
    }


def main():
    out = {
        "generated": int(time.time()),
        "refresh_sec": int(os.environ.get("DASHBOARD_REFRESH_SECS", "60")),
        "observer_dests": [d for d in (os.environ.get("OBSERVER_DESTS", "") or "").replace(",", " ").split() if d],
        # ip -> friendly name, so the console can say "desktop" not "192.168.1.50"
        # Substring patterns for the monitoring stack's own traffic. Display-level
        # on purpose - see config.env.example for why BPF cannot do this.
        "infra_domains": [d.strip() for d in (os.environ.get("INFRA_DOMAINS", "") or "").split(",") if d.strip()],
        "device_names": dict(
            kv.split("=", 1) for kv in
            (os.environ.get("DEVICE_NAMES", "") or "").split(",")
            if "=" in kv
        ),
        "config": {
            "rotate_secs": int(os.environ.get("ROTATE_SECS", 120)),
            "pcap_retention_days": int(os.environ.get("PCAP_RETENTION_DAYS", 7)),
            "max_pcap_mb": int(os.environ.get("MAX_PCAP_BYTES", 268435456)) // 1048576,
            # The console must use the SAME lead time as the watchdog, or the two
            # disagree about what counts as a problem and the page cries wolf.
            "mem_lead_mins": int(os.environ.get("MEM_LEAD_MINS", 30)),
        },
        "mem": meminfo(),
        "trend": mem_trend(),
        "consumers": cached("consumers", 300, lambda: {"rows": consumers()})["rows"],
        "watchers": watchers(),
        "queues": queues(),
        "fs": probe_fs(),
        "snapshots": cached("snapshots", 600, snapshots),
        "incidents": incidents(),
        "cluster": cached("cluster", 120, cluster),
    }
    dest = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("status.json")
    # Write-then-rename: the page polls this file, and a half-written JSON would
    # make it show an error every refresh cycle rather than the previous value.
    tmp = dest.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(out, separators=(",", ":")))
    tmp.replace(dest)
    print(f"{dest}  ({len(json.dumps(out))} bytes)")


if __name__ == "__main__":
    main()
