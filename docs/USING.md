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

## Two habits worth keeping

**Always run a control.** "No results" and "no data in that window" look
identical. Before concluding something did not happen, re-run without the filter
and confirm the window contains anything at all. The `from`/`to` parsing on
`/mapi/agg` is not always literal.

**Verify enrichment against an authoritative source** before acting on it.
GeoIP and ASN attribution are the usual culprits — see above.
