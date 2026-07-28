# Using the data

Four ways in, all over the same data and the same basic auth:

| | URL | Best for |
|---|---|---|
| **Dashboards** | `/dashboards/` | Curated views, ad-hoc charts |
| **Dev Tools Console** | `/dashboards/app/dev_tools#/console` | Raw OpenSearch queries — the most powerful |
| **Arkime** | `/arkime/` | Session drill-down, downloading actual packets |
| **APIs** | `/mapi/`, `/arkime/api/` | Scripting and agents |

---

## The one thing to understand first

**Everything lands in a single index pattern: `arkime_sessions3-*`.**

Arkime sessions, Zeek protocol logs, and Suricata alerts are all normalised into
one schema there. You do not query "the Zeek index" — you filter the shared index
by `event.dataset`:

```
event.dataset:dns      Zeek DNS
event.dataset:conn     Zeek connections
event.dataset:ssl      Zeek TLS
event.dataset:notice   Zeek notices
event.dataset:alert    Suricata alerts
event.dataset:session  Arkime sessions
```

Start any investigation by asking what you actually have:

```
GET arkime_sessions3-*/_search
{ "size": 0, "aggs": { "d": { "terms": { "field": "event.dataset", "size": 30 } } } }
```

The other patterns are `malcolm_beats_*` (Malcolm's own system logs) and
`arkime_stats_*` (capture statistics).

---

## Dev Tools Console

`/dashboards/app/dev_tools#/console`. Type on the left, hit the green triangle,
results on the right. Ctrl/Cmd-Enter also submits.

**What talked to what, by hostname:**
```
GET arkime_sessions3-*/_search
{
  "size": 0,
  "query": { "term": { "event.dataset": "ssl" } },
  "aggs": { "sni": { "terms": { "field": "server.domain", "size": 25 } } }
}
```

**Everything one host did, most recent first:**
```
GET arkime_sessions3-*/_search
{
  "size": 20,
  "query": { "term": { "source.ip": "192.168.1.100" } },
  "sort": [ { "@timestamp": "desc" } ],
  "_source": [ "@timestamp","source.ip","destination.ip","destination.port","server.domain","event.dataset" ]
}
```

**DNS queries in the last 15 minutes:**
```
GET arkime_sessions3-*/_search
{
  "size": 0,
  "query": { "bool": { "filter": [
    { "term":  { "event.dataset": "dns" } },
    { "range": { "@timestamp": { "gte": "now-15m" } } }
  ]}},
  "aggs": { "q": { "terms": { "field": "dns.host", "size": 20 } } }
}
```

**Suricata alerts by signature:**
```
GET arkime_sessions3-*/_search
{
  "size": 0,
  "query": { "term": { "event.dataset": "alert" } },
  "aggs": { "sig": { "terms": { "field": "rule.name", "size": 20 } } }
}
```

**Traffic volume over time (spot beaconing):**
```
GET arkime_sessions3-*/_search
{
  "size": 0,
  "query": { "term": { "destination.ip": "203.0.113.10" } },
  "aggs": { "over_time": { "date_histogram": { "field": "@timestamp", "fixed_interval": "5m" } } }
}
```

Evenly spaced buckets of near-identical size are the signature of automated
check-in rather than human activity.

**Useful housekeeping:**
```
GET _cat/indices?v&s=store.size:desc
GET _cluster/health
```

The same console is scriptable, which is how an agent drives it:

```sh
curl -sk -u admin:PASS -X POST -H 'osd-xsrf: true' \
  'https://HOST/dashboards/api/console/proxy?path=arkime_sessions3-*/_search&method=POST' \
  -H 'Content-Type: application/json' \
  -d '{"size":0,"aggs":{"d":{"terms":{"field":"event.dataset"}}}}'
```

---

## Field names that will waste your time

- **`tls.client.server_name` never aggregates.** It is mapped as `text`, so it
  returns zero buckets with no error even though documents clearly carry it.
  Use **`server.domain`**, `zeek.ssl.server_name`, or `related.hosts`.
- **A `-` bucket means "field absent"**, not a real value. It is usually the
  largest bucket. Ignore it.
- **`destination.as.full` / `destination.geo.country_name` come from a bundled
  GeoIP database that is stale.** Reallocated ranges still show their previous
  owner — Hetzner space resolving to Iranian ISPs, for example. Confirm with
  RDAP before believing any country or ASN:
  ```sh
  curl -s https://rdap.db.ripe.net/ip/91.98.9.143 | jq '{handle,name,country}'
  ```

Fields that reliably work: `source.ip`, `destination.ip`, `destination.port`,
`event.dataset`, `dns.host`, `server.domain`, `rule.name`,
`zeek.notice.note`, `network.transport`.

---

## Discover

`/dashboards/app/data-explorer/discover`. Pick the `arkime_sessions3-*` index
pattern, set the time range (top right — it defaults narrow, which is the usual
reason "there's no data"), then filter with DQL:

```
event.dataset:dns and source.ip:192.168.1.100
event.dataset:alert and not rule.name:*STUN*
server.domain:*microsoft* or server.domain:*windows*
destination.port:22 and not destination.ip:192.168.1.0/24
```

Add columns from the left field list rather than reading raw JSON.

With the enhanced experience enabled you also get **Workspaces** (saved
groupings of dashboards/queries) and **Explore**, alongside the classic view.

---

## Dashboards worth opening

There are 111. Most cover protocols a home network never speaks — expect the
whole ICS/IoT section, plus SMB / NTLM / Kerberos / LDAP / RDP / Telnet / SNMP,
to be empty unless you run Windows domain services or industrial kit.

Start with:

- **Overview** — traffic at a glance
- **Security Overview** and **Suricata Alerts** — triage; expect the volume to be
  mostly benign (checksum offload, STUN/NAT traversal)
- **Connections** and **IP Connections Tree** — the "who talks to whom" map
- **DNS** — usually the fastest way to spot a misconfigured or chatty device
- **SSL / X.509 Certificates** — TLS destinations and who issued their certs
- **Zeek Known Summary** — discovered hosts and services
- **Asset Interaction Analysis** — device-centric view

Which ones actually have data:
```
GET arkime_sessions3-*/_search
{ "size": 0, "aggs": { "d": { "terms": { "field": "event.dataset", "size": 50 } } } }
```

---

## Arkime

`/arkime/`. This is where you go from "a session exists" to "here are the bytes".

- The search bar uses Arkime's own syntax, not DQL: `ip.dst == 8.8.8.8 && port.dst == 443`
- **Sessions** → click any row → **Packets** shows the decoded payload
- **PCAP export** downloads the real packets for Wireshark — this is the payoff
  for `SNAPLEN=0`; with a reduced snaplen you get headers only
- **Connections** renders the node/link graph
- **SPI View** breaks a field down by value — good for "what else did this host do"

Set the time range in the top right; it defaults to the last hour.

---

## Scripting it

```sh
tools/mapi /mapi/version                                # health + cluster state
tools/mapi "/mapi/agg/dns.host?from=1 hour ago"         # aggregate any field
tools/mapi "/mapi/agg/server.domain?from=24 hours ago"
tools/mq   '{"event.dataset":"notice"}' 20              # raw documents
tools/mapi "/arkime/api/sessions?length=20&date=-1"
tools/mapi "/arkime/api/connections?date=-1&srcField=source.ip&dstField=destination.ip"
tools/mapi "/dashboards/api/saved_objects/_find?type=dashboard&per_page=100&fields=title"
```

`/mapi/agg/<field>` accepts a `filter` parameter of URL-encoded JSON:

```sh
tools/mapi "/mapi/agg/server.domain?filter=%7B%22source.ip%22%3A%22192.168.1.100%22%7D"
```

---

## Standard sweep

`tools/investigate [hours]` runs the whole routine in one pass: corpus by
dataset, LAN devices, top TLS destinations, periodicity analysis, Suricata
alerts, inbound exposure, and plaintext HTTP.

```sh
tools/investigate 3
```

The periodicity section separates **beacons** (new connection per check-in, many
ephemeral source ports) from **long-lived flows** (one socket held open). Both
look identical on time-bucket coverage alone, which is why raw "contacted every
interval" heuristics flag every VPN tunnel as C2.

Traffic worth recognising before calling anything suspicious:

| Pattern | Almost always |
|---|---|
| `:41641` UDP, incl. to off-LAN gateways like `192.168.0.1` | Tailscale endpoint discovery |
| `:3478` | STUN / NAT traversal |
| `:5351` UDP to the router, high rate | NAT-PMP/PCP port mapping (Tailscale, torrent clients, consoles) |
| `:1900` to the router | SSDP/UPnP discovery |
| `:5355` to `224.0.0.252` / `ff02::1:3` | LLMNR — a *failing* name lookup, repeated |
| `:10001` broadcast | Ubiquiti device discovery |

A sustained LLMNR flood is worth chasing: it means something is repeatedly
resolving a name that does not exist, usually a container or app pointed at a
hostname that is not reachable from where it runs.

## Two habits worth keeping

**Always run a control.** "No results" and "no data in that window" look
identical. Before concluding something did not happen, re-run without the filter
and confirm the window contains anything at all. The `from`/`to` parsing on
`/mapi/agg` is not always literal.

**Verify enrichment against an authoritative source** before acting on it.
GeoIP and ASN attribution are the usual culprits — see above.

## Keeping it running

```sh
tools/watchdog          # one line per problem, silent when healthy
tools/watchdog --heal   # also restart pcap-monitor if the publisher stalled
```

Worth running on a timer. The failure it exists for — the pcap publisher going
silent while its process, its container and every other container all report
healthy — is invisible to `docker compose ps`, and costs you every packet
captured until someone notices the graphs are flat. See
[GOTCHAS.md](GOTCHAS.md).

Every run also records a memory sample and, before any repair, writes a
forensics dump of the stalled watcher to `${TMPDIR:-/tmp}/er4-watchdog/forensics/`.
Collect before you heal, or every incident stays unexplained.

## The console — one page for pipeline health and network behaviour

```sh
tools/dashboard install   # bind-mount it into Malcolm's nginx (once)
tools/dashboard build     # re-render after changing the template
tools/dashboard url       # where to open it
```

Then open **`https://<collector>/nsm/`**, behind the same auth as everything else.

It exists because Arkime and OpenSearch Dashboards answer "what is on the
network" well and cannot answer "is the pipeline healthy" at all — the failures
here (a watcher thread dying, the host running out of memory, captures landing in
a directory nothing polls, a snapshot never proven to restore) do not exist in
any index, so no amount of dashboarding inside OpenSearch can surface them.

**Top half — pipeline health**, from `status.json`: memory with its trend and
projected time-to-floor, watcher threads against their learned healthy peak,
spool queue depth and head age, 9p scan latency against the settle window,
cluster and snapshot state, and a count of every stall the watchdog has healed.

**Live activity and devices** are the two panels for "what is my PC doing right
now": a feed of the most recent named connections (time, device, domain,
address) and a per-device breakdown of the services each LAN device talks to,
with real byte totals. Set `DEVICE_NAMES` in `config.env` to see `desktop`
instead of `192.168.1.50` — device names are barely present on the wire, so this
is configured rather than guessed, and the address stays visible beside the name.

**The rest of the network view**, queried live: upload destinations (with
`OBSERVER_DESTS` rows tagged, or your own tooling tops the list), top talkers,
TLS domains, DNS and NXDOMAIN, unanswered LLMNR/mDNS, Suricata alerts and
destination ports. Click any row to drill in: volume and up/down ratio,
periodicity with source-port cardinality — which is what separates a beacon from
one long-lived connection — peers, ports, TLS domains, and a link into Arkime for
the packets.

No new service runs for any of this. The page is static and served by Malcolm's
own nginx, which makes it same-origin with the APIs, so the browser does the
querying. Only `status.json` is written server-side.

**Keep the feed fresh.** Every `tools/watchdog` run rewrites it, so on a 5-minute
watchdog timer the header will read up to `5m old`. For the 60-second cadence the
page polls at, run the refresher alongside the watchdog:

```sh
nohup tools/dashboard watch 60 >/tmp/dashboard-watch.log 2>&1 &
```

It costs about two seconds of work per minute (the expensive parts are cached).
The header always shows the AGE of the data, so a refresher that dies reads as
stale rather than quietly serving old numbers as current — check there first if
the numbers look frozen.

## Snapshots — the thing that makes an index loss survivable

An OOM-corrupted index **cannot be repaired**: `allocate_empty_primary` still
opens the corrupt files, so the only exit is to delete it. Losing
`arkime_stats_v30` that way cost the UI graphs. The same event against a session
index costs the sessions.

```sh
tools/snapshot init      # register the repository + daily policy (once)
tools/snapshot list      # what exists, how big, how old
tools/snapshot verify    # PROVE a snapshot restores, without touching live data
tools/snapshot take      # snapshot now (refuses to run under memory pressure)
```

`verify` is the one to run periodically. It restores the newest snapshot into a
`restore-check-*` index alongside the live data, compares document counts, and
deletes the copy — so "we have backups" is a measurement rather than a belief.

To actually recover, after deleting the corrupt index:

```sh
tools/osapi es DELETE arkime_sessions3-260728          # the corrupt one
tools/snapshot restore <snapshot-name> arkime_sessions3-260728
tools/osapi es GET _cat/aliases/arkime_sessions3       # confirm the alias came back
```

This costs no memory, no JVM and no new process: the repository lives under
Malcolm's existing `path.repo` mount and OpenSearch's own job scheduler runs it.

## Memory pressure — `MEMORY FALLING`, `MEMORY FREE LOW`, `MEMORY LOW`

```sh
tools/memguard           # state, trend, largest consumers, and what it would do
tools/memguard --act     # run the mitigation ladder as far as the state warrants
```

Three warnings, in the order you want to meet them:

| warning | meaning |
|---|---|
| `MEMORY FALLING` | still comfortable, but the trend crosses the floor within `MEM_LEAD_MINS` |
| `MEMORY FREE LOW` | `MemFree` is low even though `MemAvailable` looks fine — one slow reclaim from failing |
| `MEMORY LOW` | at the floor; this is the state that destroyed an index |

The ladder, each rung reporting the memory it actually reclaimed:

1. **drop the Docker VM page cache** — typically frees 1-3 GB instantly. Not free
   of charge: everything re-read afterwards comes back over 9p.
2. **clear OpenSearch caches and flush the translog** — gives heap back and
   reduces what is in flight if the host does fall over.
3. **stop logstash** — last resort. It is both the largest sheddable consumer
   (~2-3 GB) and the source of the writes that make a flush fail. Captures keep
   landing on disk and filebeat holds its position, so nothing is lost; the cost
   is ingest latency. `tools/watchdog` restarts it automatically once there is
   real headroom.

None of this fixes the underlying problem, which is that the collector shares a
host with heavy compute jobs. `tools/memguard` prints the largest consumers so
that argument can be made with numbers.

**Before reaching for the ladder, check the heaps.** The ladder absorbs pressure;
right-sizing removes it. Measure the live set rather than trusting "heap used" —
a JVM fills what it is given:

```sh
tools/osapi es GET '_nodes/stats/jvm?filter_path=nodes.*.jvm.mem.pools.old,nodes.*.jvm.gc.collectors'
```

Old-gen occupancy and a full-GC count of zero mean the heap is oversized. Change
`OPENSEARCH_HEAP` in `config.env`, re-run `./install.sh collector` (or edit
`config/opensearch.env` directly) and restart that one service. Snapshot first.

## Getting told about it

```sh
ALERT_WEBHOOK=https://ntfy.sh/your-private-topic   # in config.env
```

`tools/watchdog` posts its findings there whenever it reports anything, rate
limited per problem-set so a condition lasting an hour pages once rather than
twelve times. Unset, it stays silent. This matters more than any panel: the
console is excellent while you are looking at it and useless at 04:00.

### `MEMORY LOW` / `SWAP PRESSURE`

Act on these before anything else, and **do not restart your way out of them**.

OpenSearch reports an out-of-memory host as a **corrupt index**: a flush cannot
read its segment infos, Lucene raises `CorruptIndexException`, the shard becomes
unassignable and that data is gone for good. The innermost cause in the log is
`Cannot allocate memory`, several `nested:` clauses down, so the top of the stack
trace blames the disk. It happened here at 143 MB available with 13.5 GB of 16 GB
swap in use, and the first symptom of any kind was a red cluster.

```sh
free -m
ps -eo rss,pid,etimes,comm --sort=-rss | head
docker stats --no-stream --format '{{.MemUsage}}\t{{.Name}}'
```

The stack is not usually the culprit — OpenSearch and Logstash are sized
deliberately (see `OPENSEARCH_HEAP`). Look for whatever else shares the host.
Reclaim what is safe (`sync; echo 3 > /proc/sys/vm/drop_caches` in a privileged
container recovers page cache immediately), and **wait for a heavy job to finish
rather than restarting OpenSearch under pressure** — a restart needs memory it
does not have.

Recovering a shard lost this way is in [GOTCHAS.md](GOTCHAS.md); the short
version is that you cannot, and that retrying the allocation while the host is
still short burns the five-attempt budget in seconds.

### Quarantined captures

A single oversized capture deadlocks the mover and stops the whole pipeline, so
`sensor/rotate.sh` diverts anything over `MAX_PCAP_BYTES` (default 50 MB) into
`pcap/quarantine/` instead of queueing it. Nothing polls that directory, so a
quarantined capture is **never analysed** — it is a deliberate blind spot traded
for keeping the pipeline alive.

```sh
tools/prune-pcap --dry-run          # reports quarantine footprint on every run
docker logs er4-sensor | grep quarantined
```

**Quarantine should now be empty almost always.** Captures over `MAX_PCAP_BYTES`
are split into `PCAP_SPLIT_MB` pieces and queued, not set aside — the only thing
that still lands here is a capture `tcpdump` could not read at all. Files
accumulating is therefore a finding, not routine.

```sh
tools/pcap-limit                    # size distribution, and what the cap costs
tools/unquarantine --dry-run        # what would be recovered, and how
tools/unquarantine                  # re-queue it all, paced
```

If you need to re-test the ceiling — for instance after changing `ROTATE_SECS` —
`tools/pcap-limit probe <file>` feeds one capture back through the live pipeline
attended, aborts by pulling it out again if it does not clear, and does so well
inside the watchdog's `STALL_SECS` so the healer does not start restarting
containers underneath the experiment.

Quarantine has its own retention (`QUARANTINE_RETENTION_DAYS`, default 30 days —
longer than the routine archive, because these are rare and kept deliberately).

## Is the pipeline late because the filesystem is slow?

```sh
tools/stall-probe start      # sample every watcher's kernel wait channel
tools/stall-probe report     # 9p latency percentiles vs the settle window
tools/stall-probe dump       # deep forensics right now
```

The number to watch is a directory scan of `pcap/processed` against
`PCAP_PIPELINE_POLLING_ASSUME_CLOSED_SEC` (10 s). Once a scan takes longer than
the settle window the watcher is late by construction and it looks exactly like a
silent stall. Scan cost is linear in file count, so it worsens as the archive
fills toward its retention steady state — `report` projects both.

## Reading the upload leaderboard

`tools/investigate` ranks destinations by bytes **sent from** your network.
Asymmetry is the interesting axis: normal browsing is download-heavy, so a
destination that receives far more than it sends is a backup, a sync client,
telemetry — or something you did not install on purpose.

Two traps when interpreting it:

- **Use `client.bytes` / `server.bytes`, not `source.bytes` / `destination.bytes`.**
  The client/server pair is relative to who *initiated* the connection, which is
  what "uploaded" means. Source/destination is per-packet direction and will
  mislead you on long-lived flows.
- **`conn` records carry no SNI.** The hostname lives in the `ssl` dataset, so a
  volume aggregation shows `-` for every destination. Resolve separately:
  ```sh
  tools/osapi ppl "source=arkime_sessions3-* | where \`destination.ip\`='IP' \
    and \`event.dataset\`='ssl' | stats count() by \`server.domain\`"
  ```

A destination with **no SNI and no DNS lookup** is worth a second look, but it is
not automatically suspicious — VPN mesh clients connect to relay IPs from a
baked-in list and never resolve a name, which reproduces that signature exactly.
Check RDAP before drawing conclusions.

## Reading DNS health

`tools/investigate` reports the split between internal and genuinely external
lookups, plus the NXDOMAIN leaderboard.

Expect the internal share to be **large** — often 80-95%. Container names,
search-suffix expansion (`name`, `name.lan`, `name.local`), and reverse lookups
for RFC1918 space all escape to the LAN resolver, and one misconfigured
application can account for most of it on its own. A container pointed at a
database hostname it cannot resolve retried every 3 seconds and produced ~2,500
NXDOMAIN queries; on a quiet network that alone was a quarter of all traffic.

The NXDOMAIN list is the fastest way to find that class of problem: **names that
do not exist, asked repeatedly, are always a misconfiguration.** Worth acting on
even when harmless, because the volume buries everything else.

**The NXDOMAIN list is only half the picture.** When a name fails, the OS falls
back to LLMNR and mDNS, which are multicast to every device on the segment, and
an unanswered multicast query returns nothing at all — no rcode, so nothing to
count as NXDOMAIN. `tools/investigate` reports those separately under
*Unanswered LLMNR/mDNS*. Expect it to be several times larger than the NXDOMAIN
figure for the same name; measured here, 8x.

Treat that line as a security finding rather than noise. A host asking the whole
segment "who is `postgres`?" thousands of times is the Responder / NTLM-relay
setup — any machine that answers becomes that host, and the asker will
authenticate to it. Fixing the broken lookup removes the exposure; disabling
LLMNR and mDNS on the host removes the class.

Two things that will show up there and are not misconfigurations:

- `wpad.lan` / `wpad.<domain>` — Windows proxy auto-discovery. Harmless here, but
  WPAD is a known hijack vector and is worth disabling in the OS.
- Your own monitoring stack's service names, if it runs on the same host — a
  container that briefly cannot resolve a sibling forwards the query upstream.

**High entropy is a shortlist, not a verdict.** DGA domains score high in the
first label, but so do CDN and telemetry hostnames — `ohttp-relay-safebrowsing-
chrome.google.fastly-edge.com` tops the list on a perfectly clean network.
Eyeball the names; do not alert on the score.

## Decrypted flows

If TLS interception is enabled (see [MITM.md](MITM.md)), decrypted HTTP lands in
`mitm-flows-*`:

```sh
tools/osapi ppl 'source=mitm-flows-* | stats count() by `url.domain` | sort - `count()` | head 20'
tools/osapi ppl 'source=mitm-flows-* | where `http.response.status_code` >= 400 | fields `url.full`, `http.response.status_code` | head 20'
tools/osapi es GET 'mitm-flows-*/_search?q=url.domain:example.com&size=5'
```

Separate index, same field names as the passive schema — `source.ip`,
`destination.ip`, `url.full` — so a query written for one works against the
other. Add `mitm-flows-*` as an index pattern to chart it in Dashboards.

Credential headers are stored as `<redacted>` by default;
`MITM_REDACT_HEADERS=false` stores them verbatim for full-fidelity forensics.
Each document records which mode it was captured under:

```sh
tools/osapi ppl 'source=mitm-flows-* | stats count() by `mitm.redacted`'
```

Treat the index as sensitive either way — it contains decrypted payloads.

## Hunting

`tools/investigate` includes a hunt section: non-standard destination ports, and
external destinations reached with no SNI and no preceding DNS lookup.

Both are *identification* prompts, not alarms. On a real network the odd-port
list is dominated by games, VPNs and P2P, and the no-DNS list by mesh VPN relays
that dial IPs from a baked-in map. The work is naming each one, not reacting to
it.

**Never attribute by GeoIP or ASN from this data.** The bundled database is stale
enough to place Hetzner ranges in Iran, which manufactures alarming findings out
of nothing. Confirm with RDAP:

```sh
curl -s https://rdap.db.ripe.net/ip/<ip>  | jq '{name,country}'
curl -s https://rdap.arin.net/registry/ip/<ip> | jq '{name}'
```

**Correlation by time window is the cheapest way to name an unknown flow.** An
unexplained UDP session peaking 20:30-22:00 and stopping at midnight, alongside
a game's TLS API peaking in the same window, is that game's traffic. Check what
else the host was doing:

```sh
tools/osapi es POST 'arkime_sessions3-*/_search' '{"size":0,
  "query":{"bool":{"filter":[{"term":{"event.dataset":"ssl"}},
    {"range":{"@timestamp":{"gte":"<start>","lt":"<end>"}}}]}},
  "aggs":{"d":{"terms":{"field":"server.domain","size":10}}}}'
```

Signals that turned out to be worth nothing here, so you can skip them: rare
destinations (632 external, 217 seen twice or less — all CDN churn), and most
Suricata INFO rules. Signals worth keeping: upload asymmetry, and any port that
is not 80/443/53.
