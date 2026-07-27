#!/usr/bin/env python3
"""Rewrite Malcolm's docker-compose.yml for an out-of-tree data root.

Two edits, both load-bearing:

1. Every bind-mount `source:` becomes an absolute path. Malcolm ships them
   relative (`./pcap`, `./opensearch`, ...). Under Docker Desktop a relative
   source resolves against a *different view* of the filesystem, so the
   container gets a newly created empty directory instead of the one holding
   your config and data. Nothing errors - services just start against nothing.
   Bulk data paths are redirected to the data root; everything else stays with
   the Malcolm tree.

2. The `*-live` services and `pcap-capture` are moved to an opt-in profile.
   They exist to sniff the collector's own NIC, which a router-sensor design
   never does, and they idle at hundreds of MB of RAM.

Idempotent.
"""
import argparse
import re
import sys

# Paths that grow without bound and belong on the data volume. Order matters:
# longest-first so "opensearch-backup" is not swallowed by "opensearch".
DATA_PREFIXES = [
    "opensearch-backup",
    "opensearch",
    "filescan-logs",
    "suricata-logs",
    "zeek-logs",
    "netbox/media",
    "postgres",
    "valkey",
    "pcap",
]

LIVE_SERVICES = {"arkime-live", "zeek-live", "suricata-live", "pcap-capture"}
LIVE_PROFILE = "live-capture"


def is_data(rel: str) -> bool:
    return any(rel == p or rel.startswith(p + "/") for p in DATA_PREFIXES)


def rewrite_sources(text: str, malcolm_base: str, data_base: str) -> tuple[str, int, int]:
    counts = {"data": 0, "cfg": 0}

    def repl(m: re.Match) -> str:
        indent, path = m.group(1), m.group(2)
        rel = path[2:].rstrip("/")
        trailing = "/" if path.endswith("/") else ""
        if is_data(rel):
            counts["data"] += 1
            base = data_base
        else:
            counts["cfg"] += 1
            base = malcolm_base
        return f"{indent}source: {base.rstrip('/')}/{rel}{trailing}"

    out = re.sub(r"( *)source: (\./\S*)", repl, text)
    return out, counts["data"], counts["cfg"]


def gate_live_services(text: str) -> tuple[str, list[str]]:
    """Move live-capture services to an opt-in profile.

    Malcolm writes profiles in flow style (`profiles: ["malcolm", "hedgehog"]`),
    so a block-sequence regex finds nothing and silently reports success.
    """
    lines = text.split("\n")
    current = None
    changed = []
    for i, line in enumerate(lines):
        m = re.match(r"^  ([a-z0-9-]+):\s*$", line)
        if m:
            current = m.group(1)
        elif current in LIVE_SERVICES and re.match(r"^    profiles:", line):
            lines[i] = f'    profiles: ["{LIVE_PROFILE}"]'
            changed.append(current)
            current = None
    return "\n".join(lines), changed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("compose")
    ap.add_argument("--malcolm-base", required=True)
    ap.add_argument("--data-base", required=True)
    args = ap.parse_args()

    with open(args.compose) as fh:
        original = fh.read()

    text, n_data, n_cfg = rewrite_sources(original, args.malcolm_base, args.data_base)
    text, gated = gate_live_services(text)

    leftover = re.findall(r"source: \./\S*", text)
    if leftover:
        print(f"ERROR: {len(leftover)} relative sources remain, e.g. {leftover[:3]}",
              file=sys.stderr)
        return 1

    if text != original:
        with open(args.compose, "w") as fh:
            fh.write(text)

    print(f"  rewrote {n_data + n_cfg} bind sources "
          f"({n_data} -> data root, {n_cfg} -> malcolm tree)")
    print(f"  gated behind '{LIVE_PROFILE}': {', '.join(gated) if gated else 'already gated'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
