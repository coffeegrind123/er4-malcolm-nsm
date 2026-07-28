"""Export decrypted flows as NDJSON for ingestion into the analysis stack.

This exists because the obvious integration does not work. mitmproxy does not
write a TLS keylog for the sessions it terminates (SSLKEYLOGFILE produced
nothing), and Arkime has no keylog-based decryption at all - so "hand the keys
to Arkime and let it decrypt the router's pcaps" is not a real path. Both ends
of that idea are false.

What does work: mitmproxy already holds the plaintext, so it writes the
decrypted metadata and content here, tools/mitm-ingest ships it, and it lands in
OpenSearch alongside the passive capture. One line per flow.

Field names deliberately mirror the passive schema (source.ip, destination.ip,
url.full, http.*) so a decrypted flow and a Zeek record can be searched with the
same query rather than needing a separate mental model.
"""
import json
import os
from datetime import datetime, timezone

from mitmproxy import http

OUT = os.environ.get("MITM_NDJSON", "/flows/mitm-flows.ndjson")
# Bodies are the entire point of decrypting, but they are also how you fill a
# disk and how you end up storing credentials you did not mean to keep.
MAX_BODY = int(os.environ.get("MITM_MAX_BODY", "8192"))
CAPTURE_BODIES = os.environ.get("MITM_CAPTURE_BODIES", "true").lower() == "true"

# Credential headers. Redacted by default so that a casual "let me see what my
# network is doing" does not quietly build a searchable store of session tokens.
#
# Set MITM_REDACT_HEADERS=false for full fidelity - forensics, debugging your own
# auth flows, reproducing a failing request. Everything is then written verbatim,
# which is the point, and the flow index becomes credential material: anyone with
# read access to OpenSearch can replay those sessions, and the tokens stay valid
# until they expire or are rotated.
REDACT = os.environ.get("MITM_REDACT_HEADERS", "true").lower() != "false"

REDACT_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "api-key", "x-csrf-token",
}
# Add your own with MITM_REDACT_EXTRA="x-session,x-internal-token"
REDACT_HEADERS |= {
    h.strip().lower()
    for h in os.environ.get("MITM_REDACT_EXTRA", "").split(",")
    if h.strip()
}

if not REDACT:
    print("[export_ndjson] MITM_REDACT_HEADERS=false - capturing credential "
          "headers verbatim; treat mitm-flows-* as secret material")


def _body(message) -> dict:
    if not CAPTURE_BODIES or not message.content:
        return {"bytes": len(message.content or b"")}
    raw = message.content[:MAX_BODY]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"bytes": len(message.content), "binary": True}
    return {
        "bytes": len(message.content),
        "truncated": len(message.content) > MAX_BODY,
        "text": text,
    }


def _headers(message) -> dict:
    if not REDACT:
        return {k.lower(): v for k, v in message.headers.items()}
    return {
        k.lower(): ("<redacted>" if k.lower() in REDACT_HEADERS else v)
        for k, v in message.headers.items()
    }


def response(flow: http.HTTPFlow) -> None:
    try:
        rec = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {"dataset": "mitm", "module": "mitmproxy"},
            "source": {"ip": flow.client_conn.peername[0] if flow.client_conn.peername else None},
            "destination": {
                "ip": flow.server_conn.peername[0] if flow.server_conn.peername else None,
                "port": flow.request.port,
            },
            "url": {"full": flow.request.pretty_url, "domain": flow.request.pretty_host,
                    "path": flow.request.path.split("?")[0]},
            "http": {
                "request": {"method": flow.request.method,
                            "headers": _headers(flow.request),
                            "body": _body(flow.request)},
                "response": {"status_code": flow.response.status_code,
                             "headers": _headers(flow.response),
                             "body": _body(flow.response)},
            },
            "tls": {"version": flow.client_conn.tls_version,
                    "sni": flow.client_conn.sni},
            # Stamped per document: without it you cannot tell whether an empty
            # authorization field means "no credential" or "redacted at capture".
            "mitm": {"redacted": REDACT},
        }
        with open(OUT, "a") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
    except Exception as exc:  # never let export kill the proxy
        print(f"[export_ndjson] {type(exc).__name__}: {exc}")
