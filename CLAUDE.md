# Working agreement for this repo

This repo is public. It is tooling for monitoring a real private network, so
the single most important rule is about what must never reach a commit.

## Never commit sensitive data — generalize instead

**Nothing describing the real monitored network is ever committed or pushed.**
Not in code, not in comments, not in docs, not in commit messages, not in
examples, not in test fixtures.

That means, always replaced with placeholders:

| Real thing | Use instead |
|---|---|
| Actual LAN addressing, router/host IPs | `192.168.1.0/24`, `192.168.1.1`, `192.168.1.100` |
| Public/WAN IPs, VPS addresses | RFC 5737 — `203.0.113.10`, `198.51.100.0/24` |
| Real host filesystem paths | `//c/Users/YOU/...`, `/path/to/data` |
| Hostnames, tailnet names, SSIDs, domains | `example.internal`, `HOSTNAME` |
| MAC addresses, device serials | `aa:bb:cc:dd:ee:ff` |
| Usernames, account names, email | `YOU`, `admin`, `user@example.com` |
| Private project or service names | a generic description of what it does |

Never committed at all, in any form:

- Passwords, password hashes, API tokens, session cookies
- SSH private keys, TLS keys, certificates, `known_hosts`
- `config.env` (only `config.env.example`, with placeholder values)
- PCAP files or any capture artifact, in whole or in excerpt
- Exported dashboards/saved objects that embed real hostnames or addresses
- Log excerpts, query output, or screenshots containing real addresses

`.gitignore` covers `config.env`, `keys/`, `*.pem`, `*.key`, `*.pcap` — treat
that as a backstop, not the control. The control is checking before you commit.

## Findings belong here as lessons, not as evidence

Investigation results are valuable and worth writing up — but publish the
*technique* and the *reasoning*, never the network they came from.

- Good: "a fixed source port distinguishes a long-lived flow from a beacon"
- Good: "GeoLite2 still maps some reallocated ranges to their previous holder"
- Bad: "`<real LAN IP>` talks to `<real vendor hostname>` every 60s"

A worked example needs a real-looking address, not a real one. Third-party
public infrastructure used to illustrate a checkable fact (a registry lookup
that anyone can reproduce) is fine; it says nothing about the monitored network.

## Scrub the commit, not the working tree

A search-and-replace over the whole directory will also rewrite `config.env` —
which is gitignored, so it was never the problem, but *is* what the running
deployment reads. Replacing real addresses there points the live system at
placeholder hosts and paths. That is how capture gets stopped by a
documentation change.

Restrict any sanitisation pass to tracked files, and exclude local config:

```sh
git ls-files | grep -vE '^(config\.env|keys/)' | xargs sed -i 's/REAL/PLACEHOLDER/g'
```

## Check before every push

```sh
git diff --cached | grep -niE '192\.168\.[0-9]+\.|10\.[0-9]+\.|BEGIN .*PRIVATE KEY|password|token'
git ls-files | grep -E 'config\.env$|\.pcap$|keys/'      # must return nothing
```

Then confirm against the remote, not just the working tree — a scrub applied
after a push does not unpublish anything:

```sh
gh api repos/<owner>/<repo>/tarball/main | tar xz && grep -rniE '<your real addressing>' .
```

If real data has already been pushed, rewriting history is not sufficient on its
own — treat anything exposed (keys, tokens, passwords) as compromised and rotate
it.

## Conventions

- Scripts are idempotent; re-running is always safe.
- Every bind-mount source is an absolute path (see `docs/GOTCHAS.md`).
- Prefer verifying over asserting. Most failures in this stack are silent —
  containers report healthy, jobs report success, aggregations return `0`
  instead of an error. A negative result is worthless without a control:
  search for something you know is present using the same method first.
- When a gotcha costs real debugging time, add it to `docs/GOTCHAS.md` with
  the symptom, not just the fix — the symptom is what the next person searches
  for.
