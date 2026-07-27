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

### The bundled GeoIP database is stale
GeoLite2 still maps some reallocated ranges to their previous holders — e.g.
Hetzner's `91.98.0.0/16` and `46.225.32.0/20` resolve to Iranian ISPs, which
manufactures alarming-looking findings. Confirm ownership with RDAP before
acting on any country or ASN attribution:
```sh
curl -s https://rdap.db.ripe.net/ip/91.98.9.143 | jq '{handle,name,country}'
```
