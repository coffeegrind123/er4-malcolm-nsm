# Gotchas

Every item here was found by something failing quietly. Each one is handled by
the scripts; they are documented because if you change the scripts, these are
what will bite you.

The pattern worth internalising: **almost none of these fail loudly.** Containers
report healthy, jobs report success, aggregations return `0` rather than an
error. Verify with a control — search for something you *know* is there using
the same method — before believing an absence.

---

## Router

### `command -v tcpdump` reports missing when tcpdump exists
EdgeOS's login PATH omits `/usr/sbin`. Test the path directly (`test -x
/usr/sbin/tcpdump`). Concluding "not installed" here sends you off installing
packages on an architecture that has none.

### Hardware offload makes capture silently blind
With offload enabled the Octeon fastpath switches forwarded packets without
letting them reach the Linux stack, so libpcap sees a fraction of traffic — or
none. There is no error; the capture is just mysteriously empty. Check for an
`offload` block in `/config/config.boot` before trusting any capture.

### Key auth rejected because the home directory has a stale owner
EdgeOS can leave `/home/<user>` and `.ssh` owned by a UID from a previous
account. Under `StrictModes yes`, OpenSSH refuses `authorized_keys` when the
directory chain is owned by neither root nor the authenticating user. The
symptom is a bare `Permission denied (publickey)` with a correctly installed
key and nothing useful in the server log. Compare `id -u` against
`stat -c %u $HOME`.

### Write keys through the config tree, not `authorized_keys`
EdgeOS regenerates `~/.ssh/authorized_keys` from its config on every commit and
prints "Do not edit, all changes will be lost" into the file. Use
`set system login user <u> authentication public-keys ...`.

### No `timeout` on the router
Busybox coreutils. Background the process and kill it instead.

### The capture must exclude its own transport
The stream leaves over the same link being captured, so without a BPF exclusion
every captured byte is shipped and then captured again. Exclude the
router↔collector SSH session specifically.

---

## Docker Desktop on Windows

### Relative bind mounts resolve to an empty filesystem
This is the big one. A `./config` source does **not** resolve to the directory
you are looking at — the container gets an empty directory instead. No error;
services simply start against nothing. Every `source:` must be an absolute
Windows-style path (`//c/...`, `//d/...`).

Verify rather than assume:
```sh
docker run --rm -v //c/path/to/dir:/m alpine ls /m   # must show your files
```

### inotify does not cross the Windows file share
File watchers using the native API never fire, so the pipeline sits idle and
ingests nothing while every container reports healthy. Set
`PCAP_PIPELINE_POLLING=true` and `FILEBEAT_WATCHER_POLLING=true`.

### Ownership is whatever created the file
Data directories must be owned by uid 1000 or OpenSearch and Valkey fail to
start. A tree first written by a root-running container stays root-owned and
locks out the later non-root ones — the failure surfaces as
`java.nio.file.AccessDeniedException` or Valkey's `Can't open the append-only
file: Permission denied`.

### `docker manifest inspect` on ghcr says `denied` for public images
A stale credential in `~/.docker/config.json` is sent instead of fetching an
anonymous token. It looks exactly like the image not existing. Confirm with the
token dance before believing it:
```sh
t=$(curl -s "https://ghcr.io/token?scope=repository:idaholab/malcolm/arkime:pull" | jq -r .token)
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $t" \
  https://ghcr.io/v2/idaholab/malcolm/arkime/manifests/26.07.1
```
Pull with an empty `DOCKER_CONFIG` rather than deleting the user's credential.

---

## Malcolm

### Its own scripts need Python ≥ 3.12
`configure`, `auth_setup` and `control.py` use PEP 701 f-strings. On 3.11 you
get `SyntaxError: unterminated string literal` from an uncorrupted file. Run
them in a 3.13 container.

### `auth_setup` refuses root *and* needs a writable tree
Both at once, which a Windows bind mount cannot satisfy (root-owned 0755). Stage
the tree into a docker volume you can `chown`, run there, copy back.

### `PUID`/`PGID` must be 1000, not 0
`configure` records the UID it ran as. Run it in a root container and it writes
`PUID=0`; the entrypoint then runs `usermod -u 0`, which chowns Arkime's home —
which contains bind mounts — and Arkime exits 12 with only
`usermod: Failed to change ownership of the home directory`.

### Zeek dies on every pcap without `zeek/custom/__load__.zeek`
`./scripts/start` touches it; `docker compose up` does not. Zeek then hits
`can't open .../site/custom/__load__.zeek` and fatally errors on **every**
capture — while its container still reports **healthy**. The only visible
symptom is that no Zeek datasets ever appear. An empty file fixes it.

### Nothing logs unless `PCAP_PIPELINE_VERBOSITY` is set
The pipeline processors are silent by default and supervisord sends its own log
to `/dev/null`. Set it to `-vv` to see anything at all while debugging.

### The pipeline has two stages, watching different directories
`watch-upload` moves files from `pcap/upload` to `pcap/processed`;
`pcap_watcher.py` then watches **`processed`** and publishes to Zeek, Suricata
and Arkime over ZMQ. Looking only at `upload` misleads. ZMQ pub/sub is lossy —
a subscriber restarting misses whatever was published meanwhile, so those files
are simply never analysed.

### The pcap publisher can stop while everything still looks healthy
Observed in production. `pcap-monitor` runs two independent processes:
`watch-upload` (moves `pcap/upload` → `pcap/processed`) and `pcap-publisher`
(watches `processed` and notifies Zeek/Suricata/Arkime over ZMQ).

The publisher stopped emitting and never recovered. Everything that normally
indicates a problem said otherwise:

- the process was **alive** (`supervisorctl status` RUNNING, uptime unbroken)
- **no exception, no traceback**, nothing in its log at all
- the container stayed **healthy**, and so did all 22 others
- the mover kept working, so captures kept flowing across the disk
- `docker logs` looked busy — every line was the *other* process

The only visible symptom was the OpenSearch document count going flat while
capture files kept arriving. Fifteen minutes of traffic was moved to
`processed/` and never analysed.

Diagnosis that worked: the publisher had **0 open sockets** — not blocked on
OpenSearch, simply not doing anything. Restarting `pcap-monitor` resumed it.

`tools/watchdog` checks for this by comparing the newest capture in
`processed/` against the last publish timestamp. In healthy operation the
publish is *newer* than the file (lag is negative); during the stall the newest
file ran 900s ahead of the last publish. `--heal` restarts the container.

**Captures during the stall are recoverable** — they are sitting in
`processed/`, just never analysed. Copy them back into `upload/` to re-queue
them. Only re-queue files the publisher never announced, or you will duplicate
sessions; the last `📫` line in its log tells you where it stopped.

### Files already in a spool directory are never picked up
The upload watchers act on **created** events only. A capture that is already
sitting in `pcap/upload` when the watcher starts is logged and then ignored
forever — the debug line shows `➋` (modified) where a healthy file shows `➊`
(created), and the `👓`/`🖅` move lines never follow.

`touch` does **not** fix it. Touching produces another *modified* event, so the
file stays stuck — and worse, it resets the mtime, which hides the backlog from
any age check based on mtime. Make the file genuinely new instead:

```sh
mkdir -p /pcap/requeue
mv /pcap/upload/*.pcap /pcap/requeue/ && sleep 20 && mv /pcap/requeue/*.pcap /pcap/upload/
```

Found 13 captures from the first hour of operation still sitting unprocessed
five hours later. For the same reason, queue-age checks should derive age from
the **capture timestamp in the filename**, not from mtime.

### A deep queue and a stopped queue need different responses
After any stall the backlog can be hours old while the consumer works through it
perfectly well. Restarting *then* is actively harmful — each restart costs the
container's startup delay and drops whatever was in flight, so a watchdog on a
5-minute heal loop can keep a queue permanently backlogged and never let it
catch up. That is a self-inflicted outage.

Check for drain activity before restarting anything: if the consumer has logged
extract/publish events recently, it is working — report the backlog and leave it
alone. Only restart when the queue is old **and** nothing is draining.

### Do not alert on a flat document count
Two ways that false-positives: an idle network legitimately indexes nothing, and
a **date-pinned index name** (`arkime_sessions3-260727`) stops growing at every
UTC midnight rollover while ingestion is perfectly healthy. Query the wildcard
`arkime_sessions3-*`, and alert on "captures arriving but nothing published"
rather than on the count alone.

### Zeek writes tarballs, filebeat unpacks them
Zeek emits `.tar.gz` into `zeek-logs/upload`;
`filebeat-watch-zeeklogs-uploads-folder.py` extracts them.
`filebeat-process-zeek-folder.sh` explicitly **prunes** `upload/`, so watching
that script for progress shows "job succeeded" while nothing is consumed.

### `*-live` containers start even with live capture disabled
`arkime-live`, `zeek-live`, `suricata-live` and `pcap-capture` are in the
`malcolm` profile regardless of `*_LIVE_CAPTURE=false`, idling at hundreds of MB.
With a router sensor they are pure waste. Note the profiles are written in flow
style (`profiles: ["malcolm", "hedgehog"]`) — a block-sequence regex matches
nothing and reports success having changed nothing.

### `configure` sizes JVM heap against total, not available, RAM
It will hand OpenSearch 10g on a box with 13g free and something else already
using it. Size against what is actually free.

---

## Querying

### `tls.client.server_name` never aggregates
Mapped as `text`, so `/mapi/agg/tls.client.server_name` returns zero buckets
with no error even though documents plainly carry the field. Use
`server.domain`, `zeek.ssl.server_name` or `related.hosts`.

### A `-` bucket means "field absent", not a value.

### `from`/`to` parsing is unreliable — always run a control
Absolute timestamps can be offset. Before reading "0 results" as "this did not
happen", re-run without the filter to confirm the window contains data at all.

### PPL `like()` refuses IP-typed fields
`source.ip` and `destination.ip` are mapped as OpenSearch type `ip`, not string,
so `like(\`source.ip\`, "192.168.1.%")` fails with *"LIKE function expects
{[STRING,STRING,BOOLEAN]}, but got [IP,STRING,BOOLEAN]"*. Use `cidrmatch`:

```sql
source=arkime_sessions3-* | where cidrmatch(`source.ip`, '192.168.0.0/16')
```

Skip it and a "LAN devices" listing quietly fills with external peers instead of
erroring.

### PPL: dotted field names need backticks, and `span()` only goes in `by`
`stats count() by source.ip` parses but misbehaves — quote as
`` `source.ip` ``. The same applies to aggregate aliases when sorting:
``sort - `count()` ``. And `span()` is a grouping expression, so
`dc(span(@timestamp, 5m))` is a syntax error; it belongs in the `by` clause.

### A long-lived connection is indistinguishable from a perfect beacon
Bucket-coverage periodicity analysis — "contacted in every 5-minute bucket with
near-zero variance" — flags a single persistent TLS session or VPN tunnel
exactly as strongly as it flags real C2 beaconing. Both score ~100% coverage
and a very low coefficient of variation.

The discriminator is **source-port cardinality**. A beacon opens a new
connection per check-in, so it burns many ephemeral source ports; a persistent
flow reuses one socket. Aggregate `cardinality` on `source.port` alongside the
date histogram — `tools/investigate` does this, and without it every Tailscale
tunnel and long-poll connection reads as malicious.

### The bundled GeoIP database is stale
GeoLite2 still maps some reallocated ranges to their previous holders — e.g.
Hetzner's `91.98.0.0/16` and `46.225.32.0/20` resolve to Iranian ISPs, which
manufactures alarming-looking findings. Confirm ownership with RDAP before
acting on any country or ASN attribution:
```sh
curl -s https://rdap.db.ripe.net/ip/91.98.9.143 | jq '{handle,name,country}'
```

### A queue can drain steadily and still never make progress
This one cost two wrong diagnoses, so it is worth the detail.

Symptom: 67 Zeek tarballs pending, unchanged across half an hour. Extract events
were flowing the whole time (3–5 per 5 minutes) and the consumer looked healthy.

**Wrong diagnosis 1 — "the consumer is too slow."** Extract gaps measured 62s,
63s, 58s, 62s, which reads as a ~60s poll cycle handling one file each. It is
not: those gaps were just the rate at which *new* files arrived (a 60s capture
rotation). The consumer's actual capacity, once measured properly, was **68
files in under 100 seconds**. Rate-of-arrival is not rate-of-service, and you
cannot tell them apart from a healthy system.

**Wrong diagnosis 2 — "the backlog will converge."** Also wrong, because the
queue was not FIFO in practice.

**Actual cause:** the watchers act on *created* events only, so the 67 files that
were already present when the watcher restarted were skipped **forever** while
every new arrival sailed past them. Steady-state count, steady event flow,
permanently stranded head.

The diagnostic that settles it: **watch the oldest entry, not the count.** If
the head never changes while the queue drains, entries are being passed over,
not processed. `tools/watchdog` tracks this across runs and reports
`QUEUE HEAD STUCK`.

**Restarting does not fix it** — after a restart those files are still
pre-existing. Re-present them as new by moving them out and back in:

```sh
mkdir -p /queue/.requeue
mv /queue/dir/* /queue/.requeue/ && sleep 20 && mv /queue/.requeue/* /queue/dir/
```

Draining 68 stranded tarballs this way recovered a window that had held Suricata
alerts only, restoring its Zeek `dns`, `conn` and `ssl` records.

`ROTATE_SECS` is set to 300 rather than 60 — fewer, larger captures mean less
per-file overhead — but note that is a tidiness choice, **not** the fix for a
backlog. The fix is above.

### Stopping the sensor strands the capture it was writing
`tcpdump -z` only runs the rotate hook when tcpdump itself closes a file. Kill
the container and whatever it was mid-write stays in `staging/` forever — no
process will ever move it, and that traffic is silently lost. Every restart
leaks one more.

`capture.sh` now sweeps `staging/` on startup, moving anything older than one
rotation interval into `upload/` (the age test is what keeps it from grabbing
the live file when a sensor is already running).
