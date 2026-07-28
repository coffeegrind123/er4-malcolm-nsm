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

## Definition of done — run this without being asked

A change is not finished when the code works. Before saying it is done, do all
four. Do not wait to be prompted, and do not just assert the result — show the
check.

**1. Docs and tools track the change.** If behaviour, a config key, a path or a
failure mode changed, then in the same pass update `config.env.example` (the key
*and* the reasoning), `README.md` if it affects setup or operation,
`docs/USING.md` if an operator would need to do something about it, and
`docs/GOTCHAS.md` if it cost real debugging time — symptom first, because the
symptom is what the next person searches for. A new directory or artifact needs
an owner: something must bound its growth, or it will grow forever in a place
nobody looks.

**2. Sanitisation, derived from local truth rather than memory.** Build the
search terms from the gitignored files, so the check cannot miss a value nobody
remembered to look for:

```sh
# needles from config.env / keys/, then scan TRACKED files only
git ls-files -z | xargs -0 grep -n -F "$REAL_VALUE"          # must be empty
git ls-files | grep -E 'config\.env$|^keys/|\.pcap$|\.pem$'  # must be empty
```

Placeholders (`192.168.1.x`, `203.0.113.x`, `//c/Users/YOU/...`) are expected in
tracked files and are not hits. Real observed domains, private project names,
device models and tailnet/host names count as private data just as much as an IP
does — findings are published as technique, never as evidence.

**3. Every negative result needs a control.** A clean grep proves nothing until
the same command has found something you know is there. Run the control first
and show it. This applies to any "not found", "no matches", "0 results" claim
anywhere in this repo, not just sanitisation.

**4. Verify against the remote, not the working tree.** A scrub after a push
unpublishes nothing:

```sh
gh api repos/<owner>/<repo>/tarball/main | tar xz
grep -rn "$REAL_VALUE" .    # with a control, per rule 3
```

If real data was already pushed, rewriting history is not sufficient — treat
anything exposed as compromised and rotate it.

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
