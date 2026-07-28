# TLS interception ("naked capture")

The passive sensor sees everything *around* the encryption — who talked to whom,
hostnames, sizes, timing. This adds the payloads.

It is off by default, and it is the one part of this project that **modifies
traffic** rather than observing it. Read the whole page before enabling.

---

## What it cannot do, and why

**The CA cannot be installed automatically.** This is the first thing people ask
and the answer is a firm no — not a limitation of this tooling, but the entire
security model of TLS. If a network could push a root certificate that clients
silently trusted, every café Wi-Fi could read your banking session. Every device
you want to intercept needs the CA installed **deliberately, once, by hand**.

**Certificate-pinned clients will not be intercepted — they will break.** An app
that ships its own CA ignores the system trust store entirely and simply fails
to connect. That is not a misconfiguration to fix; it is the app working
correctly. IoT devices are the common case: an air-quality sensor pinning its
vendor's private CA will stop reporting the moment you intercept it, and the
only fix is to exclude it.

**You will not decrypt what you already captured.** Interception decrypts
traffic *going forward*. The obvious workaround — export TLS keys and use them
on the stored pcaps — does not work here, and both halves of it were tested:
mitmproxy writes no keylog for sessions it terminates, and Arkime has no
keylog-based decryption at all.

---

## Two ways to route traffic in

### Proxy mode (start here)

An explicit HTTP proxy. Nothing is redirected; a client uses it because it was
configured to. Blast radius is whatever you point at it.

```sh
MITM_MODE=proxy ./install.sh mitm
```

**Clients can be configured automatically via WPAD**, which is worth knowing
because most networks are already asking for it — this one had 131 `wpad.lan`
lookups from a single host, all answered NXDOMAIN. Serve a `wpad.dat` from the
router and Windows configures itself with no client-side setup:

```sh
./router/serve-wpad.sh          # serves wpad.dat + the CA over http
```

That automates the *proxy configuration*. It does not automate CA trust, and
nothing can.

A PAC file should always end with `DIRECT` as a fallback, so a dead proxy
degrades to normal browsing instead of taking the network offline.

### Transparent mode (network-wide)

The router policy-routes selected clients through a tunnel to the interception
node, which redirects locally into the proxy.

```
LAN client → ER-4 policy-route → WireGuard/AmneziaWG tunnel → interception node
           → iptables REDIRECT → mitmproxy transparent → real destination
```

The tunnel is not decoration. mitmproxy's transparent mode recovers the original
destination through `SO_ORIGINAL_DST`, which only works when the REDIRECT
happened **on the same host as the proxy**. A plain DNAT from the router rewrites
the destination, and the proxy then has no idea where the client was going. The
router must therefore *route* rather than *translate*, and the tunnel is what
carries routed packets to a collector that has no LAN presence of its own —
macvlan cannot reach the LAN from Docker Desktop, which rules out the simpler
designs.

The EdgeRouter has `amneziawg` (WireGuard-compatible) in its config tree, which
is what makes this possible on a MIPS router that can run none of the analysis
software itself.

**Fail-open is mandatory.** A policy route pointing at a dead tunnel blackholes
the client. Every rule installed by `router/setup-mitm-route.sh` is conditional
on the tunnel being up.

---

## Where decrypted traffic ends up

Flows land in OpenSearch in their own `mitm-flows-*` index, searchable next to
the passive capture:

```sh
tools/mitm-ingest              # follow and ship continuously
tools/osapi es GET 'mitm-flows-*/_search?size=5'
tools/osapi ppl 'source=mitm-flows-* | stats count() by `url.domain` | sort - `count()` | head 20'
```

A separate index is deliberate. Malcolm owns `arkime_sessions3-*` and its
mappings; injecting a foreign document shape risks mapping conflicts that would
break the passive pipeline. The field names still mirror the passive schema
(`source.ip`, `destination.ip`, `url.full`), so the same query shape works
against either.

Add `mitm-flows-*` as an index pattern in Dashboards to chart it alongside
everything else.

---

## Credential capture

Two modes, both verified:

```sh
MITM_REDACT_HEADERS=true    # default - Authorization/Cookie/API keys -> <redacted>
MITM_REDACT_HEADERS=false   # full fidelity - everything stored verbatim
MITM_REDACT_EXTRA="x-session,x-internal-token"   # additional headers to mask
```

Redaction is only the default so that "let me see what my network is doing" does
not quietly build a searchable store of session tokens. **It is not a
recommendation.** For forensics, for debugging your own auth flows, or for
reproducing a failing request, you want the real header and turning it off is
the correct call.

What changes when it is off: the flow index becomes credential material. Anyone
with read access to OpenSearch can lift a session token and replay it, and those
tokens stay valid until they expire or are rotated. That is a statement about
where the index lives and who can read it, not a reason to avoid the setting.

Every document records which mode captured it:

```sh
tools/osapi ppl 'source=mitm-flows-* | stats count() by `mitm.redacted`'
```

Without that stamp an empty `authorization` field is ambiguous — no credential
sent, or redacted at capture? Verified both ways: with redaction on, a
`Bearer` token stores as `<redacted>` while `user-agent` and the rest of the
flow survive intact; with it off, the token and cookie are stored verbatim.

Bodies are separate: truncated at `MITM_MAX_BODY`, disabled with
`MITM_CAPTURE_BODIES=false`.

Treat the flow index as sensitive in either mode — it holds decrypted payloads.
It lives on `DATA_ROOT`, and `*.ndjson` is gitignored so an export cannot be
committed by accident.

---

## Legal and practical footing

Intercepting traffic on a network you own, for devices you own, is ordinary
network administration. Intercepting other people's devices — housemates,
guests, family — is a different matter both ethically and legally in most
jurisdictions, and a guest device silently having its TLS broken is not
something they can detect or consent to.

Scope interception to specific source addresses (`MITM_CLIENTS`) rather than the
whole LAN. It is also the practical choice: fewer pinned apps break, less
volume, and a smaller index of sensitive material.
