# er4-malcolm-nsm

Reproducible network security monitoring for a home or small-office network:
an **EdgeRouter as the capture sensor**, **Malcolm** (Arkime + Zeek + Suricata +
OpenSearch) as the collector, driven entirely from the command line or a web UI.

Full packet capture, protocol decode, IDS alerting, and three HTTP APIs you can
point an agent at.

## Why the split

An EdgeRouter 4 is 32-bit MIPS **big-endian** (Cavium Octeon III, Debian 9,
~1 GB RAM). Debian dropped the `mips` BE port after stretch, and none of
Arkime / Zeek / Suricata / ntopng publish builds for it. There is no compiler
on the router and Arkime additionally needs OpenSearch. **The router cannot host
the analysis stack**, and no software upgrade changes that.

It is however an excellent *sensor*. `tcpdump` and `libpcap` are already
installed, and it is the routing chokepoint — so captures carry **pre-NAT LAN
source addresses**, which a capture taken anywhere downstream has already lost.
Sensor-on-router plus collector-off-box is the same topology Arkime and Malcolm
ship upstream.

```
  EdgeRouter (br0)                          Collector (Docker)
  tcpdump -i br0 -s 0 ──── SSH stream ────▶ er4-sensor
                                                 │ rotating pcap
                                                 ▼
                                            pcap/upload
                                                 │
                                     pcap-monitor ├─▶ Zeek     ─┐
                                                  ├─▶ Suricata ─┼─▶ Logstash ─▶ OpenSearch
                                                  └─▶ Arkime   ─┘                   │
                                                                     Arkime UI · Dashboards · APIs
```

Nothing is written to router flash — the capture is streamed over stdout, so
eMMC wear and the router's limited free space are both non-issues.

## Install

Requires: Docker with compose v2, `git`, `python3`, `sshpass`, and SSH access to
the router. ~8 GB RAM free for the collector, and a large volume for PCAP.

```sh
git clone https://github.com/<you>/er4-malcolm-nsm && cd er4-malcolm-nsm
cp config.env.example config.env
$EDITOR config.env          # router IP, collector IP, data root, heaps
./install.sh
```

Stages can be run individually: `./install.sh router|collector|sensor`.
Everything is idempotent — re-running is safe.

`./install.sh router` will prompt once for the router password, install a
dedicated SSH key through the EdgeOS config tree, and thereafter use only the
key. It also **verifies the things that silently break capture**: that
`/usr/sbin/tcpdump` exists, that hardware offload is not stealing forwarded
packets, and that the kernel is not dropping frames — then measures your actual
traffic rate so you can size storage.

## Storage and memory

Full packet capture is expensive — an idle home network runs tens of GB per day,
a busy one far more. Put `DATA_ROOT` on your largest volume. Arkime prunes the
oldest PCAP once free space falls below `ARKIME_FREESPACEG`.

To trade fidelity for volume, set `SNAPLEN=512` in `config.env`: headers, DNS
and TLS SNI survive (enough to answer "who talked to what") at roughly 10-20x
less data, but payload search is gone.

Memory is usually the binding constraint. `OPENSEARCH_HEAP` + `LOGSTASH_HEAP`
must fit in RAM that is *actually free* — Malcolm's own configure sizes them
against total system RAM and will happily over-allocate.

## Driving it

```sh
tools/mapi /mapi/version                                   # health + cluster state
tools/mapi "/mapi/agg/dns.host?from=1 hour ago"            # hostnames looked up
tools/mapi "/mapi/agg/server.domain?from=24 hours ago"     # TLS SNI destinations
tools/mapi "/mapi/agg/destination.as.full"                 # destination networks
tools/mapi "/arkime/api/sessions?length=20&date=-1"        # raw sessions
tools/mapi "/arkime/api/connections?date=-1&srcField=source.ip&dstField=destination.ip"
tools/mq   '{"event.dataset":"ssl"}' 20                    # raw documents
```

Scope any aggregation to one host:

```sh
tools/mapi "/mapi/agg/server.domain?filter=$(python3 -c 'import urllib.parse;print(urllib.parse.quote(chr(123)+chr(34)+"source.ip"+chr(34)+":"+chr(34)+"192.168.1.100"+chr(34)+chr(125)))')"
```

Three independent APIs are exposed: Malcolm's `/mapi/`, Arkime's `/arkime/api/`
(including `/connections`, which returns a node/link graph), and the OpenSearch
Dashboards saved-objects API — all behind the same basic auth, all scriptable.

## Operating

```sh
cd "$MALCOLM_DIR" && docker compose --profile malcolm up -d     # start
cd "$MALCOLM_DIR" && docker compose --profile malcolm stop      # stop
cd sensor && docker compose --env-file ../config.env -f docker-compose.sensor.yml restart
docker logs -f er4-sensor
```

Do **not** use Malcolm's `./scripts/start` — it needs Python ≥ 3.12 and assumes
a Linux host layout. This repo drives `docker compose` directly and performs the
setup steps that script would otherwise have done (see
[docs/GOTCHAS.md](docs/GOTCHAS.md)).

## Security notes

- nginx binds `0.0.0.0:443`, so the UI is reachable from the whole LAN, protected
  by basic auth only. Bind it to `127.0.0.1` if that is not wanted.
- The generated admin password is written to `keys/malcolm_pw`. `keys/` is
  gitignored — do not commit it.
- The router key is a dedicated keypair; password login is left working as a
  fallback and nothing else about the router's configuration is changed.

## TLS interception (optional)

Everything above is passive — it observes without touching traffic. If you also
need payloads, `./install.sh mitm` adds an interception node, and
**[docs/MITM.md](docs/MITM.md)** covers it properly: proxy vs transparent mode,
why the router must policy-route rather than DNAT, automating client proxy
config via WPAD, and why the CA can never be installed automatically.

It is off by default and scoped to named clients. Credential headers are
redacted before anything is stored, and certificate-pinned devices will break
rather than be intercepted — that is the app working correctly, not a bug.

## Using it

**[docs/API.md](docs/API.md)** — everything in Dashboards Management, Data
Administration and Settings & Setup driven from the CLI via `tools/osapi`:
index patterns, saved objects, advanced settings, workspaces, ISM retention,
SQL/PPL, query insights, and the security admin API (which needs a client
certificate, not a password). Nothing is read-only.

**[docs/USING.md](docs/USING.md)** — how to actually interrogate the data:
Dev Tools Console queries, the single unified index everything lands in, which
of the 111 dashboards have data on a typical network, Arkime drill-down and PCAP
export, and the field names that silently return nothing.

## Read this before debugging

**[docs/GOTCHAS.md](docs/GOTCHAS.md)** — every failure mode found while building
this, and why most of them are invisible. Containers report healthy, jobs report
success, and aggregations return `0` instead of an error. The recurring lesson:
a negative result is worthless without a control.
