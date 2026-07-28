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

### A restart loop that can never succeed
The worst version of the created-events trap, and it was self-inflicted by the
watchdog rather than by Malcolm.

If a spool directory holds files that were **already there** when its watcher
started, the watcher ignores them permanently. A restart does not help: to the
restarted watcher they are still pre-existing. So drain stays at zero, the
"consumer produced no events" check fires again, and it restarts again — every
five minutes, forever, while new files pile up behind the stranded ones.

Observed live: five captures stranded from 10:05, repeated restarts of
`pcap-monitor` and `filebeat` across forty minutes, ingestion falling to zero,
and every restart making no difference because the problem was never the process.

**Restart once, then escalate.** If drain is still zero after a recent restart,
the files are stranded, not the process — re-queue them instead. `tools/watchdog`
records a per-queue restart timestamp and switches to a re-queue if the previous
restart did not restore drain within `RESTART_ESCALATE_SECS` (default 900).

The diagnostic that separates the two, when it happens to you: compare the
newest file in the *source* directory against the newest in the *destination*.
Capture landing at 10:40 while `processed/` stops at 10:05 means the mover is
the problem. Capture itself stopping means it is not.

### A stuck head has two causes needing opposite repairs
Check "is the consumer emitting anything at all" **before** "has the head
moved", or you will apply the wrong repair:

| consumer events | meaning | repair |
|---|---|---|
| none | the watcher has wedged | restart it |
| flowing | created-events trap | re-queue the strays |

Getting the order backwards re-queues files at a dead consumer. That is a no-op
— nothing is left to notice the new files — and it reads as "the repair failed"
rather than "the repair was wrong". `tools/watchdog` checks drain activity
first for exactly this reason.

The correct sequence when both are true is: restart, confirm the consumer is
emitting again, *then* re-queue. After a restart the stranded files are
pre-existing to the fresh watcher, so they need the re-queue anyway.

### Expect these stalls to recur
Four separate silent stalls were observed in one evening across `pcap-monitor`
(twice), its publisher, and `filebeat`. Container restart counts stayed at
**0** throughout — the containers never died, only the watcher threads inside
them stopped. This is not a one-off to fix and forget; run the watchdog on a
timer and let it heal.

Correlated with sustained memory pressure (~500 MiB free of 21 GiB, several GiB
swapped). Whether that is cause or coincidence is unproven, but it is the
obvious suspect and worth ruling out before chasing anything subtler.

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

### MemAvailable can look healthy while the host is one slow reclaim from failing

`MemAvailable` counts page cache as if it were already yours. Measured here:

```
MemFree  546 MB   MemAvailable 6,590 MB      <- reads as fine
after dropping the Docker VM page cache:
MemFree 5,907 MB  MemAvailable 6,662 MB      <- available barely moved
```

A check watching only `MemAvailable` cannot see that state at all. It matters
more on this deployment than it would elsewhere, because the cache being
reclaimed is backing a 9p mount 60-100x slower than local disk - so the reclaim
is slow, and an allocation that cannot wait for a slow reclaim is precisely what
fails and gets reported as a corrupt index.

Watch both. `tools/memguard` does, and its first mitigation rung converts cache
straight into free memory:

```sh
docker run --rm --privileged alpine sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'
```

It has to run inside a privileged container: Docker Desktop's VM is a different
kernel from the WSL distro, and that is where the containers' page cache lives.
Measured effect on a live host: MemFree 898 MB -> 3,855 MB. It is not free of
charge - everything re-read afterwards comes back over 9p - so it is a
pressure-relief valve, not something to run on a timer.

### A level threshold cannot be an early warning when the margin is 190 MB

Routine operation here floors at ~1,557 MB available; the corruption incident
happened at 1,369 MB. Any level trigger placed in that gap either fires
constantly or fires too late, and no amount of tuning fixes it - the margin is
the problem.

What does work is the **trajectory**. `tools/watchdog` records a sample every run
and `tools/memguard` fits a least-squares slope over the last hour, warning when
either counter is projected to cross its floor within `MEM_LEAD_MINS`. Fired for
real within the hour it was written:

```
MEMORY FALLING (5018MB available, projected to reach 1400MB in ~22 min)
trend over 60m: available -209.5 MB/min, free -468.5 MB/min
```

The old level check was silent at that moment, and would have stayed silent for
another twenty minutes. Use a fit rather than first-vs-last: memory on a shared
host sawtooths, and two unlucky endpoints either cry wolf or miss a real slide.

### "CorruptIndexException" usually means the host ran out of memory
A red cluster with `ALLOCATION_FAILED` and `CorruptIndexException` reads as disk
corruption. Read the whole nested exception before believing that:

```
FlushFailedEngineException[Flush failed];
  nested: CorruptIndexException[Hit unexpected exception while reading segment infos];
  nested: FileSystemException[/usr/share/opensearch/data/.../index: Cannot allocate memory];
```

The innermost cause is `Cannot allocate memory`. Lucene could not read its
segment infos because the *host* had no memory to do it with, and reports that
as corruption. Measured at the time: 143 MB free, 13.5 GB of 16 GB swap in use.
Disk was 16% of 9 TB and `vm.max_map_count` was 1048576 — neither was involved.

Check in this order before touching the shard: `free -m`, then the innermost
`nested:` clause, then disk, then `vm.max_map_count`.

**Do not retry the allocation while the cause is still live.** A shard gets five
allocation attempts, and under memory pressure it burns all five within seconds
and then refuses further attempts:

```
max_retry -> shard has exceeded the maximum number of retries [5]
```

You then need `POST /_cluster/reroute?retry_failed=true` just to get back to
where you were. Fix the memory first; retry second.

**`allocate_empty_primary` does not skip corrupt on-disk files.** It still opens
the existing shard directory, so it fails the same way:
`IndexShardRecoveryException[failed to fetch index version after copying it
over]`. When the files are unreadable, the index has to be deleted and recreated.

**Deleting an index races the application that writes it.** With
`action.auto_create_index: true` (the default), Arkime recreated a plain
`arkime_stats` index within seconds of the delete — which then blocked the alias,
because an index and an alias cannot share a name:

```
invalid_alias_name_exception: Invalid alias name [arkime_stats],
an index exists with the same name as the alias
```

Arkime's schema is a versioned index plus an alias (`arkime_stats_v30` +
`arkime_stats`), and the auto-created one is neither. Capture the mappings and
settings first, `docker pause` the writer, then delete/recreate/alias and
unpause. Pausing trips the container healthcheck; it clears on its own within a
couple of minutes and needs no action.

Losing `arkime_stats` costs Arkime's own node-statistics history — the UI graphs.
Sessions and PCAP live in different indices and are untouched.

### A restore test against an empty index proves nothing

Arkime ships a permanently empty `arkime_sessions3-initial` bootstrap index, and
it sorts **after** the date-stamped ones (`arkime_sessions3-260728`). So the
obvious way to pick a test index - newest by name - selects the one index that
can never demonstrate anything, and the restore returns 0 documents against 0
live. That reads as a working restore if you are only checking for errors.

Pick a test index by a date pattern (or by document count), and require the
restored count to be **greater than zero** as well as consistent with the live
one. `tools/snapshot verify` restores under a `restore-check-` rename, compares
counts, and deletes the copy - so it proves restorability without touching
anything in use. Restored slightly BELOW live is expected: the index kept being
written after the snapshot.

### Snapshot Management splits create and update across two verbs

`PUT _plugins/_sm/policies/<name>` on a policy that does **not exist** fails with:

```
Validation Failed: Sequence number and primary term must be provided
when updating a snapshot management policy
```

which reads as "it already exists" and sends you looking for a policy that is not
there. Create with `POST`; only use `PUT` (with `if_seq_no`/`if_primary_term`) to
update an existing one.

Registering a repository also proves nothing about whether it can be written to -
a wrong path or a permissions problem only surfaces on the first snapshot. Call
`POST _snapshot/<repo>/_verify` at registration time.

Malcolm already sets `path.repo` to `/opt/opensearch/backup` and already
bind-mounts it to the data disk, so a repository needs no compose change, no new
mount and no restart - which matters, because restarting OpenSearch under memory
pressure is itself a risk.

### An NXDOMAIN leaderboard cannot see the worst name-resolution failures
"Names that do not exist, asked repeatedly" is the right question, but counting
`rcode_name: NXDOMAIN` answers only half of it. When a lookup fails, the OS falls
back to **LLMNR and mDNS**, which are multicast to the whole segment — and an
unanswered multicast query produces **no response at all**, so it carries no
rcode and never reaches the leaderboard.

Measured here: 539 NXDOMAIN in an hour, against **27,134 unanswered multicast
queries in six**. The leaderboard under-reported the class by roughly 8x and
missed its single largest contributor. The same misconfigured hostname appeared
in both, so nothing looked missing — the unicast portion was just the visible tip.

Query the multicast resolvers directly and filter on the *absence* of an rcode:

```json
{"filter": [{"terms": {"destination.ip": ["224.0.0.252", "224.0.0.251"]}}],
 "must_not": [{"exists": {"field": "zeek.dns.rcode_name"}}]}
```

It is also the more serious half, and not merely noise. A host repeatedly asking
the entire segment "who is `postgres`?" is the Responder / NTLM-relay setup: any
machine that answers becomes that host. WPAD is flagged for exactly this reason;
LLMNR and mDNS are the same class.

### `track_total_hits` silently caps at 10,000
A hit total is capped at 10,000 by default, and the cap looks like data — the
count is a plausible round number rather than an error. The multicast section
above first reported exactly `10000` while its own aggregation buckets already
summed past 26,000. Pass `"track_total_hits": true` whenever the number itself is
the finding, and sanity-check a total against the buckets beneath it.

### A time-windowed heading over an unfiltered query
`tools/investigate` printed `Corpus (last 1h)` above a PPL query that carried no
time filter at all, so it counted the **entire index** under a heading claiming
one hour. Nothing errors; the number is just silently wrong, and wrong in the
direction that manufactures alarm.

Measured: the "last 1h" DNS count read **241,352** against a ~20-hour corpus.
The true hourly figure was **14,369** — about 4/s, entirely normal — but 241k in
an hour is ~67/s, which reads as a DNS storm and invites an investigation into a
problem that does not exist. This repo has a real DNS-storm finding in its
history, which makes the false positive that much more convincing.

The tell is cheap: **change the window and see whether the number moves.** If
`investigate 1` and `investigate 24` agree, the filter is not being applied.

```sh
tools/investigate 1  | sed -n '/Corpus/,/^$/p'
tools/investigate 24 | sed -n '/Corpus/,/^$/p'   # must differ
```

The ES-DSL sections filtered correctly the whole time; only the PPL ones did
not. Fixed by moving those aggregations to the same `range` filter the rest of
the script already used, rather than fighting PPL's timestamp handling.

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

### The bundled GeoIP database is from 2019
Not "a bit out of date" - `logstash-filter-geoip` vendors GeoLite2 databases
built **2019-11-18**, because MaxMind's licence change that year stopped the
plugin shipping refreshed copies. The file mtime shows the *image* build date
and looks recent, which is how this hides.

Reallocated ranges resolve to their previous owners. Confirmed against RDAP:

| IP | 2019 database | actual |
|---|---|---|
| `91.98.9.143` | AS16322 Pars Online (IR) | Hetzner Online GmbH (DE) |
| `46.225.42.92` | AS56402 Dadeh Gostar (IR) | Hetzner Online GmbH (DE) |

Two German cloud ranges reading as Iranian ISPs is exactly the finding that
sends you hunting an intrusion that does not exist.

`tools/update-geoip` installs a current DB-IP Lite ASN database - no licence key,
monthly refresh, self-identifies as GeoLite2-compatible. Check what you have with
`tools/update-geoip --check`.

**ASN only.** DBIP-City-Lite parses fine standalone but the logstash geoip filter
reads nothing usable from it: country enrichment measured **0%** against 37% on
the vendored database, with no error logged either way. City stays on the stale
copy. Acceptable, because a correct ASN organisation already answers the
question - "Hetzner Online GmbH" tells you it is not Iran whatever the country
field claims.

Only NEW documents get corrected enrichment; already-indexed documents keep what
the database said when they were written.

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

---

## Findings the monitoring itself produced

### An app with no reconnect backoff becomes the loudest thing on the network
Not a Malcolm bug — a class of problem this stack is unusually good at finding,
worth writing down because the symptom is so far from the cause.

A container was configured with a database hostname that deliberately does not
resolve locally (the real database lives elsewhere; the local service is gated
behind a compose profile). Its connection helper re-ran a full ten-attempt retry
cycle on **every query** whenever the pool was down, and a periodic refresh loop
kept calling it.

Result: ~180 failed lookups per minute, ~2,500 NXDOMAIN in the sample window —
the single largest source of DNS traffic on the LAN, drowning every other signal
in the logs. Nothing was broken from the application's point of view; it logged
a warning and carried on.

**How to find it:** the NXDOMAIN leaderboard (`tools/investigate`, DNS health).
Names that do not exist, asked thousands of times, are always a misconfiguration
somewhere. Rank by count and the offender is the top row.

**The fix is a cooldown, not a retry-count change.** Reducing attempts per cycle
just reduces the burst; the flood comes from re-running the cycle per query. One
cycle per minute took it to ~4 lookups/minute, a ~44x reduction, with no
behavioural change when the database is reachable.

Related: an unqualified single-label hostname (`postgres`) generates *two*
lookups, because the resolver also tries it with the search domain appended
(`postgres.lan`). Both come back NXDOMAIN, so the volume doubles.

### Malcolm leaks its own service names on restart
Container names (`arkime`, `opensearch`, `filebeat`, `valkey-cache`,
`pcap-monitor`) and reverse lookups for the Docker bridge appear as NXDOMAIN on
the LAN resolver. Measured per hour: `435, 88, 0, 0, 26, 99` — it tracks
container restarts, not steady state, and is a startup race where one service
queries a sibling before it is up.

It is bounded (~100 queries per restart) and self-limiting. Do **not** try to
suppress it by pinning `dns`/`dns_search` on the Malcolm services: inter-service
discovery depends on Docker's embedded resolver, and overriding it to stop a
hundred stray queries risks breaking the thing the queries are for. Filter it at
the resolver instead, or accept it.

### JVM heap sized against the machine, not the data
`configure` sets OpenSearch's heap from total system RAM. That is the wrong
input twice: it ignores how much memory is actually free, and it ignores how
much data you have.

Here it produced `-Xmx6g` — **7.6 GB resident for a 160 MB index**. Combined
with Logstash and everything else, container memory totalled 19.3 GB in a 21 GB
VM, leaving ~180 MB free and several GB swapped.

Dropping to `-Xmx4g` freed 2.4 GB and took free memory from 182 MB to 2.3 GB,
with no effect on query behaviour.

Size against the index, not the machine — roughly 1 GB heap per 20-30 GB of
index, floor of ~2g:

```sh
tools/osapi es GET '_cluster/stats?filter_path=indices.store.size_in_bytes,indices.docs.count'
```

**Do not free memory by disabling NetBox or Strelka**, tempting as it looks
(~1.5 GB between them, and both were verifiably idle here — `ZEEK_EXTRACTOR_MODE
=none` means Strelka has no input, and NetBox enriched 0 documents).
`nginx-proxy` hard-depends on `netbox`, and nginx dies outright on a missing
upstream (`host not found in upstream`), taking the whole UI with it. The heap
is the safe lever.

### Container names encode the compose project, which comes from the directory
Compose names containers `<project>-<service>-1`, and takes `<project>` from the
directory it runs in. Install to `/opt/nsm-malcolm` instead of `~/malcolm` and
every hardcoded `malcolm-*` lookup finds nothing.

That fails in the worst possible way for a health check: `docker logs` on a
container that does not exist returns no output, which the watchdog reads as
"the consumer produced no events" — a false stall on **every** run, and with
`--heal` a restart loop against a perfectly healthy pipeline.

`tools/watchdog` and `tools/osapi` derive it from `basename "$MALCOLM_DIR"`, and
`COMPOSE_PROJECT` overrides it if you set one explicitly.

### You cannot see certificates for most of your traffic (and that is the protocol)
TLS 1.3 encrypts the Certificate message. Zeek therefore emits `x509` records
only for **TLS 1.2** handshakes. Measured here: TLS 1.3 was 66% of sessions and
contributed **zero** certificate records.

Every conclusion drawn from certificate data covers the 1.2 minority, and the
issuers you can see skew toward older stacks — embedded devices and enterprise
telemetry — rather than being representative of the network. "We only have three
CAs" is an artefact, not a finding.

The same applies more broadly: **this is a passive sensor, not an interception
proxy.** It sees metadata — who talked to whom, hostnames via SNI and DNS, sizes,
timing — and full packet *bytes*, but those bytes stay encrypted. Seeing plaintext
requires either terminating TLS (a MITM proxy plus a CA installed on every
client, which certificate-pinned devices will refuse) or obtaining session keys
from the client (`SSLKEYLOGFILE`), which decrypts retroactively because the full
packets are already on disk.

---

## TLS interception

### Handing TLS keys to Arkime does not work — neither half of it
The obvious way to make decryption fit the existing stack is: export TLS master
secrets from the proxy, point Arkime at them, and let it decrypt the pcaps the
router already captured. It is wrong twice, and both halves were tested rather
than assumed:

- **mitmproxy writes no keylog for sessions it terminates.** Setting
  `SSLKEYLOGFILE` produces no file at all.
- **Arkime has no keylog-based decryption.** There is no such option; searching
  its config and `capture --help` for keylog/secret returns nothing.

What works is exporting the decrypted flows from the proxy directly — it already
holds the plaintext — as NDJSON, and shipping that into OpenSearch
(`tools/mitm-ingest`).

### Decrypted flows go in their own index, not the session index
`mitm-flows-*`, not `arkime_sessions3-*`. Malcolm owns that index and its
mappings; a foreign document shape risks mapping conflicts that break the
passive pipeline — the one thing that must keep working. Field names still
mirror the passive schema so queries transfer.

Set an explicit index template. Without one, OpenSearch infers the mapping from
the first document, and a response body that happens to look like a date or a
number poisons the field for every later flow.

### The proxy cannot recover the destination behind a DNAT
mitmproxy transparent mode uses `SO_ORIGINAL_DST`, which is populated by a
**local** iptables REDIRECT. A DNAT from an upstream router rewrites the
destination before the packet arrives, so the proxy has no idea where the client
was going. The router must *route* (policy routing) rather than *translate*, and
the interception node needs a path that preserves the original destination — a
tunnel, since macvlan cannot give a Docker Desktop container a LAN presence.

### Alpine ships neither mitmproxy nor wireguard-go
Hence the Debian base. And install the userspace WireGuard backend in the *same*
layer as the rest: a separate `RUN ... || true` produced an image with `wg-quick`
present and no backend at all, which fails at run time instead of build time.

### The observer is in the data, and it is usually the loudest thing there
Whatever does the monitoring — an agent session, a remote shell, a log shipper —
egresses from the same network it is watching. Measured on this deployment: an
agent session accounted for **1.28 GB of 1.63 GB of all upload, 79% of
everything leaving the network**, across 1075 connections.

Unlabelled, that is the single most alarming row in any volume analysis: a
massively upload-skewed flow to one external address, running all night. It
looks exactly like exfiltration, and it is your own tooling.

Set `OBSERVER_DESTS` and `tools/investigate` labels those rows instead of
ranking them as findings. The same applies to any traffic *caused* by
monitoring — remote shells, artefact uploads, the capture transport itself
(already excluded by BPF at the sensor).

More generally: the measurement perturbs the thing measured, and on a quiet home
network the perturbation can dominate. Establish what your own tooling
contributes before drawing conclusions about anything else.

### The PCAP archive grows without bound by default
`pcap/processed` is never pruned in practice. `ARKIME_FREESPACEG` only triggers
when free space drops below the threshold, and on a large disk that is years
away — measured growth here was 223 → 434 captures in 17 hours, unbounded.

That directory is what `pcap_watcher` polls every cycle, and **scan cost tracks
file count, not bytes**. A size-based cap does not fix it: at ~5 MB per capture,
even a 300 GB limit leaves ~56,000 files in one directory.

`tools/prune-pcap` bounds it by time (`PCAP_RETENTION_DAYS`, default 14). It
removes the `arkime_files` index entries *before* deleting the files, so the UI
never offers a download for a capture that has already gone.

Age is taken from the capture timestamp in the filename, never mtime — the
re-queue repair rewrites mtimes, which would make a freshly repaired capture
look new and exempt it permanently.

Session metadata is untouched and keeps its own 90-day retention. Losing a raw
capture costs the packet bytes for an old session, not the session.

### "One oversized capture deadlocks the mover" - it does not, and this cost real data

**Left here because the wrong conclusion was acted on for a day and it discarded
traffic.** The reasoning below was plausible, matched the evidence available at
the time, and was still wrong.

The symptom was real: the pipeline stopped, `pcap/upload` grew, and a 156 MB
capture was sitting at the head of the queue. Moving it aside restored flow. The
conclusion drawn - that captures over ~50 MB wedge the mover - became
`MAX_PCAP_BYTES`, and everything above it went to `pcap/quarantine`, which
nothing reads. That cost four captures totalling 334 MB in seven hours, one of
them 1 MB over the line.

Re-measured with `tools/pcap-limit`:

| test | result |
|---|---|
| 14 captures 50-106.8 MB already in `processed/` | all present in `arkime_files` - fully analysed |
| the blamed 156 MB capture, re-fed to the live pipeline | mover 18s, published 30s |
| the 51 MB capture that was 1 MB over the cap | published in 31s |

And the tell that should have been caught first: `file_processor()` logs its
`👓` line **before** it does any work, yet the original incident reported no `👓`
for the file at all. If that file had been what blocked the mover, its `👓` would
have been the last line in the log.

What actually happened is that the capture was at the head of the queue during
one of the silent watcher stalls this deployment gets every few hours (below).
Post hoc, ergo propter hoc.

**The lesson is the method, not the number.** A single incident produced a
threshold, the threshold silently discarded data, and nobody re-ran the
experiment because the pipeline looked healthy afterwards - it looked healthy
because the data was being thrown away before it could cause trouble. When a
mitigation works by dropping input, verify the input was actually the problem.

`sensor/rotate.sh` now SPLITS anything over the (much higher) cap into
pipeline-sized pieces with `tcpdump -r ... -C`, so nothing is discarded even if
some genuine ceiling does exist higher up. `tools/unquarantine` recovers whatever
the old rule set aside.

**Splitting has one trap of its own:** `tcpdump -w prefix -C n` names the first
chunk `prefix` with **no numeric suffix**, then `prefix1`, `prefix2`. A
`prefix[0-9]*` glob silently drops the first chunk - 100 MB of traffic, no error.
Glob with a bare `*`, and check that the chunk sizes sum to the original (they
will exceed it by 24 bytes per extra file, which is the pcap header).

### The original (wrong) reasoning, kept for reference
Symptom: the pipeline stops, `pcap/upload` grows, and the mover **never logs the
offending file at all** — no `👓`, no error, container healthy. Restarting it
does not help, because every restart re-encounters the same file and stops
again. Observed: a 156 MB capture held the pipeline for over an hour; moving
that one file aside restored flow immediately.

The mechanism is in `watch_common.py`. The queue is ordered, and the drain loop
calls `fileProcessor(fileName)` **synchronously, inline**, logging `🖄 processed`
only after it returns. So a single file that the processor cannot get through
blocks every file behind it, and the log line that would name it is on the far
side of the call that never returns. Head-of-line, with the evidence suppressed.

`sensor/rotate.sh` therefore refuses to queue them: anything over
`MAX_PCAP_BYTES` (default 50 MB) is moved to `pcap/quarantine`, which nothing
polls, and logged. The capture is kept for manual handling rather than deleted —
the pipeline keeps moving instead of deadlocking on one file.

**`tcpdump -C` is not the alternative.** Size-based rotation appends a numeric
suffix — `file.pcap1`, `file.pcap2` — which destroys the `.pcap` extension the
pipeline matches on, so those captures are ignored entirely. Verified, not
assumed; a naive `-C` makes things silently worse than the problem it fixes.

### Rotation interval and PCAP retention multiply into one number
They look like independent knobs and are not. Steady-state file count in the
polled archive is `(86400 / ROTATE_SECS) * PCAP_RETENTION_DAYS`, and both ends
of that range have a failure mode:

- **Rotate too slowly** and a traffic burst inside one window produces the
  oversized capture above. Measured at 300s: median 0.9 MB, p95 38 MB, max
  107 MB, 13 files over 50 MB out of 444.
- **Rotate too quickly** and the file count explodes, which is what
  `pcap_watcher` pays for on every poll. Measured cost of a full
  `scandir`+`stat` on the bind mount is **1.14 ms/entry** (450 entries = 515 ms,
  reproducible across trials).

| rotate | retention | files | scan per poll |
|---|---|---|---|
| 300s | 14d | 4,032 | ~4.6 s |
| 60s | 14d | 20,160 | ~23 s |
| 120s | 7d | 5,040 | ~5.8 s |

The settle window (`PCAP_PIPELINE_POLLING_ASSUME_CLOSED_SEC`) is 10 s. Once a
snapshot takes longer than that, the watcher is late by construction and
presents exactly like the silent stall below. Change either knob and check the
product, not the knob.

Note the drain loop itself is **not** the constraint, despite an earlier comment
in `config.env.example` claiming it processed roughly one file per poll cycle.
It iterates the whole ordered deck per pass, processes every settled file, and
breaks only at the first unsettled one, resetting its sleep to 0.5 s. Measured:
**443 files drained in ~12 seconds** when a backlog cleared. Do not size the
rotation interval against that myth.

### A watchdog that heals a fault destroys the evidence for it

Structural, and it is why the stall below stayed "unproven" through dozens of
incidents rather than through any real difficulty:

- the only thing that reliably NOTICES a stall is `tools/watchdog --heal`
- the first thing it does about one is restart the container

So every stall was repaired before anything looked at the stalled thread. Not one
of them was ever examined. The fix is not to stop healing - containment is
correct - but to collect first: `tools/watchdog` now calls `tools/stall-probe
dump` before every restart, and `tools/stall-probe start` samples each watcher's
kernel wait channel every 2 seconds continuously, so the state at the moment of
the stall is already recorded before the repair runs.

Generalises: any self-healing system needs to capture state before it heals, or
it converts every incident into an unexplained one.

### The 9p mount degrades by two orders of magnitude, and the settle window is the thing it breaks

Measured with `tools/stall-probe` over an hour of normal operation, against
`pcap/processed` holding 610 captures:

| operation | p50 | p95 | max |
|---|---|---|---|
| listdir | 560 ms | 2,680 ms | **149,480 ms** |
| stat | 2.35 ms | 47 ms | 103 ms |
| create | 2.5 ms | 12.5 ms | 118 ms |

A 149-second directory listing - 250x the median for the same operation on the
same directory - is not a different filesystem, it is the same one under
contention. There is no cold-mount penalty (checked: first and second listing of
a freshly mounted share both take ~0.55 s), so this is transient degradation.

**The number that matters is the ratio to `PCAP_PIPELINE_POLLING_ASSUME_CLOSED_SEC`
(10 s).** Once one scan takes longer than the settle window, the watcher is late
by construction and presents exactly like a silent stall: no error, no exception,
container healthy, work simply not happening.

And it gets worse on its own, because scan cost is linear in file COUNT and the
archive is nowhere near its steady state. Projected from the same measurements at
the 7-day retention steady state of 5,040 files:

| case | per scan at steady state |
|---|---|
| typical (p50) | 4.6 s - inside the window |
| tail (p95) | **22.1 s - over the window** |

That predicts stalls which are intermittent rather than constant, which is what
is observed (roughly one every 2-4 hours). Watch it with
`tools/stall-probe report`, and note it argues for keeping `PCAP_RETENTION_DAYS`
down, or for moving the hot spool directories off 9p entirely.

Use percentiles, not the mean, when reporting this: one 149 s outlier in 47
samples drags the mean to 7x the median and manufactures a number that describes
the spike rather than the system.

### The first stall whose evidence survived the repair - and it was not 9p

Captured 2026-07-28 18:30 by `tools/watchdog` calling `tools/stall-probe dump`
before healing. `zeek-logs/upload` had 4 tarballs pending, oldest 520 s, and the
consumer had produced no events.

**What the thread state showed:**

| watcher | threads |
|---|---|
| publisher | `hrtimer_nanosleep`, `futex_do_wait` x2, `do_epoll_wait` x2 |
| mover | `hrtimer_nanosleep`, `futex_do_wait` x2 |
| zeek-extract | `hrtimer_nanosleep`, `futex_do_wait` |

Not one thread in `p9_client_rpc`. Not one in state `D`. So whatever stopped that
queue, **it was not a wedged 9p syscall** - which is the leading hypothesis for
these stalls, and it does not explain this one.

The pcap pipeline was working normally throughout: the mover and publisher both
handled a capture at 18:29:39 and 18:29:53, seconds before the dump. The stall
was isolated to the Zeek tarball extractor.

**The red herring, recorded because it was convincing.** The probe history showed
the extractor running 3 threads steadily for 47 minutes, then dropping to 2 at
18:24:34 - apparently a worker dying and taking the queue with it. It does not
survive checking:

- the queue's oldest entry dated from ~18:21:23, **before** the thread went
- after the repair the extractor settled back to 2 threads and drained normally,
  so 2 is a working steady state

The third thread is transient. A "restart when the thread count drops" rule built
from that correlation would fire on a healthy extractor forever - the exact
self-inflicted restart loop this file already warns about. `tools/stall-probe
threads` exists as a diagnostic and is deliberately **not** wired into the
watchdog.

Two lessons worth more than the finding: a correlation that appears at the moment
of an incident is still only a correlation, and the cheapest test is to ask
whether the "broken" state is also present when things work.

### The silent watcher stalls: what is known, and what is not
Recurring across `pcap-monitor` (mover and publisher) and `filebeat`'s extractor.
Roughly one every 2-4 hours. `tools/watchdog --heal` contains them with no data
loss, and the honest position is that the **root cause is still unproven**.

Ruled out by measurement, so nobody repeats the work:

- **Not OOM.** Zero kernel OOM kills. Container restart counts stay at 0 — the
  containers never die, only threads inside them stop.
- **Not simply memory.** Dropping OpenSearch's heap 6g→4g freed 2.4 GB and made
  stalls roughly 2x rarer, but did not stop them. Memory contributes; it is not
  the mechanism.
- **Not unbounded directory growth.** `zeek-logs/current` sits at ~880 symlinks,
  which is *steady state* for `LOG_CLEANUP_MINUTES=360` — about 12 log types
  across 72 rotations in the retention window. The cleaner runs every minute and
  works.
- **Not dangling symlinks.** All resolve.
- **Not OpenSearch backpressure.** Cluster green, 26% heap, no old-gen GC, 305ms
  query latency while a watcher was stalled.

The one measured anomaly is **filesystem latency**. The Docker Desktop Windows
bind mount is 60-100x slower than the VM's native filesystem:

| operation | 9p bind mount | native |
|---|---|---|
| create | 3.06 ms | 0.05 ms |
| listdir | 2.12 ms | 0.02 ms |
| stat | 1.46 ms | 0.00 ms |

Every stalling watcher polls directories on that mount. A blocked 9p operation
would present exactly as observed: thread sleeping, no CPU, **zero open
sockets**, no exception, container healthy. That is a hypothesis consistent with
all the evidence, not a proven cause.

If it needs a real fix rather than containment, the change to try is moving the
**hot spool directories** (`pcap/upload`, `pcap/processed`, `zeek-logs/*`) onto a
Docker volume on the VM's own filesystem, leaving only long-term PCAP storage on
the large host disk. That removes 9p from the polling path entirely.
